"""The on-aircraft agent.

Responsibilities, in order:

1. hold a locally generated identity (never transmitted);
2. enrol once with a single-use token, then re-authenticate by signing a challenge;
3. publish a signed X25519 + ML-KEM-768 bundle;
4. establish the two-party hybrid session with the ground station;
5. encrypt every telemetry frame locally and upload only opaque envelopes;
6. decrypt uplink commands locally and inject them toward the autopilot.

The server never sees a plaintext frame in either direction.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field

from .api import ApiError, PrahariClient
from .crypto import identity as identity_proto
from .keystore import Identity, Keystore, generate_identity
from .link import LinkError, SecureLink, SessionUnavailable
from .sources import TelemetrySource

log = logging.getLogger(__name__)


@dataclass
class AgentConfig:
    base_url: str
    callsign: str
    keystore_path: str
    enrollment_token: str | None = None
    channel_id: str | None = None
    heartbeat_interval_s: float = 15.0
    command_poll_interval_s: float = 0.5
    reconnect_backoff_s: float = 2.0
    max_backoff_s: float = 30.0
    stats: dict = field(default_factory=dict)


class BridgeAgent:
    def __init__(self, config: AgentConfig, source: TelemetrySource, client: PrahariClient):
        self.config = config
        self.source = source
        self.client = client
        self.keystore = Keystore(config.keystore_path)
        self.identity: Identity | None = None
        self.user_id: str | None = None
        self.link: SecureLink | None = None
        self._stop = threading.Event()
        self._seen_message_ids: set[str] = set()
        self.frames_sent = 0
        self.commands_received = 0

    # -- identity and credentials ---------------------------------------------

    def _load_or_create_identity(self) -> tuple[Identity, dict]:
        if self.keystore.exists():
            identity, meta = self.keystore.load()
            log.info("loaded existing identity for %s", self.config.callsign)
            return identity, meta
        identity = generate_identity()
        meta = {"callsign": self.config.callsign, "enrolled": False}
        self.keystore.save(identity, meta)
        log.info("generated a new identity for %s", self.config.callsign)
        return identity, meta

    def _authenticate(self, identity: Identity, meta: dict) -> dict:
        """Enrol on first run; thereafter renew by signing a device challenge."""
        if not meta.get("enrolled"):
            if not self.config.enrollment_token:
                raise LinkError(
                    f"{self.config.callsign} is not enrolled and no enrolment token was "
                    "supplied. Provision it with POST /api/v2/fleet/uavs and pass "
                    "--enrollment-token."
                )
            result = self.client.enroll(
                callsign=self.config.callsign,
                enrollment_token=self.config.enrollment_token,
                ed25519_public_key=identity.ed25519_public,
            )
            meta.update(enrolled=True, user_id=result["user_id"])
            self.keystore.save(identity, meta)
            log.info("enrolled %s", self.config.callsign)
            return result

        challenge = self.client.device_challenge(self.config.callsign)
        result = self.client.device_token(
            callsign=self.config.callsign,
            challenge_signature=identity.sign(challenge.encode("utf-8")),
        )
        log.info("re-authenticated %s", self.config.callsign)
        return result

    def _publish_bundle(self, identity: Identity) -> None:
        challenge = self.client.challenge()
        payload = identity_proto.bundle_signing_payload(
            x25519_public_key=identity.x25519_public,
            ml_kem_encapsulation_key=identity.ml_kem_encapsulation_key,
        )
        self.client.publish_keys(
            x25519_public_key=identity.x25519_public,
            ml_kem_encapsulation_key=identity.ml_kem_encapsulation_key,
            challenge_signature=identity.sign(challenge.encode("utf-8")),
            bundle_signature=identity.sign(payload),
        )
        log.info("published signed X25519 + ML-KEM-768 bundle")

    def ensure_identity(self) -> str:
        """Enrol (or re-authenticate) and publish the signed key bundle.

        Split out from :meth:`bootstrap` because the operator cannot create the link
        channel until the aircraft has a verified bundle to bind a session to.
        """
        identity, meta = self._load_or_create_identity()
        auth = self._authenticate(identity, meta)
        self.identity = identity
        self.user_id = auth["user_id"]
        if not auth.get("key_verified"):
            self._publish_bundle(identity)
        return self.user_id

    def bootstrap(self) -> None:
        if self.identity is None:
            self.ensure_identity()
        identity = self.identity
        assert identity is not None
        _, meta = self.keystore.load()

        channel_id = self.config.channel_id or meta.get("channel_id")
        if not channel_id:
            raise LinkError(
                "no link channel configured. The operator must call "
                f"POST /api/v2/fleet/uavs/{self.config.callsign}/link and pass the "
                "resulting channel id with --channel-id."
            )
        if meta.get("channel_id") != channel_id:
            meta["channel_id"] = channel_id
            self.keystore.save(identity, meta)

        self.link = SecureLink(
            self.client, identity, user_id=self.user_id, channel_id=channel_id
        )

    # -- runtime loops ---------------------------------------------------------

    def _reauthenticate(self) -> None:
        assert self.identity is not None
        challenge = self.client.device_challenge(self.config.callsign)
        self.client.device_token(
            callsign=self.config.callsign,
            challenge_signature=self.identity.sign(challenge.encode("utf-8")),
        )

    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.config.heartbeat_interval_s):
            try:
                self.client.heartbeat()
            except ApiError as error:
                if error.status_code == 401:
                    self._reauthenticate()
                else:
                    log.warning("heartbeat failed: %s", error)
            except Exception as error:  # pragma: no cover - network noise
                log.warning("heartbeat error: %s", error)

    def _command_loop(self) -> None:
        """Decrypt ground-station uplink and hand it to the autopilot."""
        assert self.link is not None
        while not self._stop.wait(self.config.command_poll_interval_s):
            try:
                messages = self.client.list_messages(self.link.channel_id, limit=50)
            except ApiError as error:
                if error.status_code == 401:
                    self._reauthenticate()
                continue
            except Exception:  # pragma: no cover - network noise
                continue

            for message in messages:
                if message["id"] in self._seen_message_ids:
                    continue
                self._seen_message_ids.add(message["id"])
                if message["sender_id"] == self.user_id:
                    continue  # our own telemetry echoed back
                try:
                    plaintext = self.link.decrypt(
                        message["envelope_b64"],
                        sender_id=message["sender_id"],
                        epoch=message["key_epoch"],
                    )
                    command = json.loads(plaintext)
                except (LinkError, ValueError) as error:
                    log.warning("undecryptable uplink %s: %s", message["id"], error)
                    continue
                self.commands_received += 1
                accepted = self.source.send_command(command)
                log.info(
                    "uplink command %s -> %s",
                    command.get("command", command.get("type", "?")),
                    "accepted" if accepted else "ignored",
                )

            # Bound memory on a long sortie; ids are only used for dedupe.
            if len(self._seen_message_ids) > 5000:
                self._seen_message_ids = set(list(self._seen_message_ids)[-1000:])

    def run(self, *, max_frames: int | None = None) -> None:
        assert self.link is not None

        backoff = self.config.reconnect_backoff_s
        while not self._stop.is_set():
            try:
                self.link.establish()
                break
            except SessionUnavailable as error:
                log.info("%s; retrying in %.0fs", error, backoff)
                if self._stop.wait(backoff):
                    return
                backoff = min(backoff * 2, self.config.max_backoff_s)

        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._command_loop, daemon=True).start()

        log.info("encrypted link up; streaming telemetry")
        for frame in self.source.frames():
            if self._stop.is_set():
                break
            payload = json.dumps(frame, separators=(",", ":")).encode("utf-8")
            try:
                self.link.send(payload)
                self.frames_sent += 1
            except ApiError as error:
                if error.status_code == 401:
                    self._reauthenticate()
                    continue
                log.warning("frame upload failed: %s", error)
                time.sleep(self.config.reconnect_backoff_s)
                continue
            except LinkError as error:
                log.error("link error: %s", error)
                time.sleep(self.config.reconnect_backoff_s)
                continue

            if max_frames is not None and self.frames_sent >= max_frames:
                break

        self.stop()

    def stop(self) -> None:
        self._stop.set()
        self.source.close()
