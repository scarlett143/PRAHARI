"""Two-party hybrid session handling for the aircraft side of the link.

This mirrors the browser's ``crypto/session.js`` exactly: same deterministic initiator
rule, same signed offer, same X25519 + ML-KEM-768 -> HKDF-SHA256 derivation, same AAD.
The aircraft is not a privileged peer -- it runs the same protocol a human runs.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from .api import ApiError, PrahariClient, b64d, b64e
from .crypto import aead, hybrid, identity as identity_proto
from .keystore import Identity

log = logging.getLogger(__name__)


class LinkError(RuntimeError):
    pass


class SessionUnavailable(LinkError):
    """The peer has not published its half of the handshake yet. Retry later."""


@dataclass
class SessionState:
    channel_id: str
    key_epoch: int
    key: bytes


class SecureLink:
    """Establishes and maintains the encrypted C2 link for one channel."""

    def __init__(
        self,
        client: PrahariClient,
        identity: Identity,
        *,
        user_id: str,
        channel_id: str,
    ):
        self.client = client
        self.identity = identity
        self.user_id = user_id
        self.channel_id = channel_id
        self._session: SessionState | None = None

    # -- session establishment -------------------------------------------------

    def _private_bundle(self) -> hybrid.HybridPrivateBundle:
        return hybrid.HybridPrivateBundle(
            self.identity.x25519_private, self.identity.ml_kem_decapsulation_key
        )

    def _public_bundle(self) -> hybrid.HybridPublicBundle:
        return hybrid.HybridPublicBundle(
            self.identity.x25519_public, self.identity.ml_kem_encapsulation_key
        )

    def _verify_peer_bundle(self, bundle: dict) -> hybrid.HybridPublicBundle:
        x_public = b64d(bundle["x25519_public_key"])
        kem_public = b64d(bundle["ml_kem_encapsulation_key"])
        payload = identity_proto.bundle_signing_payload(
            x25519_public_key=x_public, ml_kem_encapsulation_key=kem_public
        )
        if not identity_proto.verify_ed25519_signature(
            public_key=b64d(bundle["ed25519_public_key"]),
            message=payload,
            signature=b64d(bundle["bundle_signature"]),
        ):
            raise LinkError(f"peer {bundle['username']!r} has an invalid signed key bundle")
        return hybrid.HybridPublicBundle(x_public, kem_public)

    def _as_initiator(self, channel: dict, peer: dict) -> bytes:
        peer_bundle = self._verify_peer_bundle(self.client.key_bundle(peer["username"]))
        ciphertext, key = hybrid.initiate(peer_bundle)
        epoch = channel["key_epoch"]
        payload = identity_proto.session_offer_signing_payload(
            channel_id=self.channel_id,
            key_epoch=epoch,
            responder_id=peer["id"],
            x25519_ephemeral_public=ciphertext.x25519_ephemeral_public,
            ml_kem_ciphertext=ciphertext.ml_kem_ciphertext,
        )
        offer = {
            "channel_id": self.channel_id,
            "key_epoch": epoch,
            "responder_id": peer["id"],
            "x25519_ephemeral_public": b64e(ciphertext.x25519_ephemeral_public),
            "ml_kem_ciphertext": b64e(ciphertext.ml_kem_ciphertext),
            "offer_signature": b64e(self.identity.sign(payload)),
        }
        try:
            stored = self.client.post_offer(offer)
        except ApiError as error:
            if error.code == "session_offer_exists":
                raise LinkError(
                    "a different offer already exists for this epoch and its ephemeral "
                    "secret is not held on this aircraft; rotate the epoch"
                ) from None
            raise

        # The epoch holds exactly one offer. If the server echoed a different one, this
        # key is unreproducible by the peer and every frame would fail authentication.
        if (
            stored["x25519_ephemeral_public"] != offer["x25519_ephemeral_public"]
            or stored["ml_kem_ciphertext"] != offer["ml_kem_ciphertext"]
        ):
            raise LinkError("server returned a different session offer; rotate the epoch")
        return key

    def _as_responder(self, channel: dict, peer: dict) -> bytes:
        epoch = channel["key_epoch"]
        try:
            offer = self.client.get_offer(self.channel_id, epoch)
        except ApiError as error:
            if error.status_code == 404:
                raise SessionUnavailable(
                    "waiting for the ground station to publish the session offer"
                ) from None
            raise

        if offer["responder_id"] != self.user_id:
            raise LinkError("session offer is not addressed to this aircraft")

        initiator_bundle = self.client.key_bundle(peer["username"])
        self._verify_peer_bundle(initiator_bundle)
        ephemeral = b64d(offer["x25519_ephemeral_public"])
        kem_ciphertext = b64d(offer["ml_kem_ciphertext"])
        payload = identity_proto.session_offer_signing_payload(
            channel_id=self.channel_id,
            key_epoch=offer["key_epoch"],
            responder_id=offer["responder_id"],
            x25519_ephemeral_public=ephemeral,
            ml_kem_ciphertext=kem_ciphertext,
        )
        if not identity_proto.verify_ed25519_signature(
            public_key=b64d(initiator_bundle["ed25519_public_key"]),
            message=payload,
            signature=b64d(offer["offer_signature"]),
        ):
            raise LinkError("session offer signature is invalid")

        return hybrid.respond(
            self._private_bundle(),
            self._public_bundle(),
            hybrid.HybridCiphertext(ephemeral, kem_ciphertext),
        )

    def establish(self, *, force: bool = False) -> SessionState:
        channel = self.client.channel(self.channel_id)
        epoch = channel["key_epoch"]
        if not force and self._session and self._session.key_epoch == epoch:
            return self._session

        if not channel.get("hybrid_session_supported"):
            raise LinkError("link channel must hold exactly two members")

        peer = next(
            (member for member in channel["members"] if member["id"] != self.user_id), None
        )
        if peer is None:
            raise LinkError("no peer in the link channel")

        if channel["session_initiator_id"] == self.user_id:
            key = self._as_initiator(channel, peer)
            role = "initiator"
        else:
            key = self._as_responder(channel, peer)
            role = "responder"

        log.info(
            "hybrid session established as %s for channel %s epoch %s",
            role,
            self.channel_id,
            epoch,
        )
        self._session = SessionState(self.channel_id, epoch, key)
        return self._session

    # -- framing ---------------------------------------------------------------

    def send(self, payload: bytes) -> dict:
        """Encrypt one frame locally and hand the server an opaque envelope."""
        session = self.establish()
        aad = aead.build_aad(
            sender_id=self.user_id, channel_id=self.channel_id, epoch=session.key_epoch
        )
        envelope = aead.encrypt(session.key, payload, aad).to_wire()
        try:
            return self.client.send_envelope(
                client_message_id=uuid.uuid4().hex,
                channel_id=self.channel_id,
                key_epoch=session.key_epoch,
                envelope=envelope,
            )
        except ApiError as error:
            if error.code == "rekey_required":
                log.info("epoch exhausted (%s); rotating", error.detail.get("reason"))
                self.client.rotate_epoch(self.channel_id)
                self.establish(force=True)
                return self.send(payload)
            if error.status_code == 409 and "wrong key epoch" in str(error.detail):
                self.establish(force=True)
                return self.send(payload)
            raise

    def decrypt(self, envelope_b64: str, *, sender_id: str, epoch: int) -> bytes:
        session = self.establish()
        if epoch != session.key_epoch:
            raise LinkError(f"no session key held for epoch {epoch}")
        aad = aead.build_aad(
            sender_id=sender_id, channel_id=self.channel_id, epoch=epoch
        )
        return aead.decrypt(session.key, aead.Envelope.from_wire(b64d(envelope_b64)), aad)
