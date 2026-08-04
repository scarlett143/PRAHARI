"""Thin PRAHARI API client for the on-aircraft agent."""
from __future__ import annotations

import base64
from typing import Any

import httpx


class ApiError(RuntimeError):
    def __init__(self, status_code: int, detail: Any):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")

    @property
    def code(self) -> str | None:
        """Structured error code when the server returned one."""
        return self.detail.get("code") if isinstance(self.detail, dict) else None


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value)


class PrahariClient:
    def __init__(self, base_url: str, *, timeout: float = 15.0, transport=None):
        """``transport`` lets tests drive the ASGI app in-process instead of over TCP."""
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self.base_url, timeout=timeout, transport=transport
        )
        self._token: str | None = None

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "PrahariClient":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    @property
    def token(self) -> str | None:
        return self._token

    @token.setter
    def token(self, value: str | None) -> None:
        self._token = value

    def request(self, method: str, path: str, **kwargs) -> Any:
        headers = dict(kwargs.pop("headers", {}))
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        response = self._client.request(method, path, headers=headers, **kwargs)
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            raise ApiError(response.status_code, detail)
        if not response.content:
            return None
        return response.json()

    # -- enrolment -------------------------------------------------------------

    def enroll(self, *, callsign: str, enrollment_token: str, ed25519_public_key: bytes) -> dict:
        result = self.request(
            "POST",
            "/api/v2/fleet/enroll",
            json={
                "callsign": callsign,
                "enrollment_token": enrollment_token,
                "ed25519_public_key": b64e(ed25519_public_key),
            },
        )
        self._token = result["access_token"]
        return result

    def login_with_token(self, access_token: str) -> dict:
        self._token = access_token
        return self.request("GET", "/api/v2/auth/me")

    def device_challenge(self, callsign: str) -> str:
        return self.request(
            "POST", "/api/v2/fleet/auth/challenge", json={"callsign": callsign}
        )["challenge"]

    def device_token(self, *, callsign: str, challenge_signature: bytes) -> dict:
        result = self.request(
            "POST",
            "/api/v2/fleet/auth/token",
            json={
                "callsign": callsign,
                "challenge_signature": b64e(challenge_signature),
            },
        )
        self._token = result["access_token"]
        return result

    # -- identity --------------------------------------------------------------

    def challenge(self) -> str:
        return self.request("POST", "/api/v2/auth/challenge", json={})["challenge"]

    def publish_keys(
        self,
        *,
        x25519_public_key: bytes,
        ml_kem_encapsulation_key: bytes,
        challenge_signature: bytes,
        bundle_signature: bytes,
    ) -> dict:
        return self.request(
            "POST",
            "/api/v2/keys/publish",
            json={
                "x25519_public_key": b64e(x25519_public_key),
                "ml_kem_encapsulation_key": b64e(ml_kem_encapsulation_key),
                "challenge_signature": b64e(challenge_signature),
                "bundle_signature": b64e(bundle_signature),
            },
        )

    def key_bundle(self, username: str) -> dict:
        return self.request("GET", f"/api/v2/keys/{username}")

    def me(self) -> dict:
        return self.request("GET", "/api/v2/auth/me")

    # -- channel / session -----------------------------------------------------

    def channel(self, channel_id: str) -> dict:
        return self.request("GET", f"/api/v2/channels/{channel_id}")

    def post_offer(self, offer: dict) -> dict:
        return self.request("POST", "/api/v2/sessions/offers", json=offer)

    def get_offer(self, channel_id: str, epoch: int) -> dict:
        return self.request("GET", f"/api/v2/sessions/offers/{channel_id}", params={"epoch": epoch})

    def rotate_epoch(self, channel_id: str) -> dict:
        return self.request("POST", f"/api/v2/channels/{channel_id}/rotate-key", json={})

    # -- messaging -------------------------------------------------------------

    def send_envelope(
        self, *, client_message_id: str, channel_id: str, key_epoch: int, envelope: bytes
    ) -> dict:
        return self.request(
            "POST",
            "/api/v2/messages",
            json={
                "client_message_id": client_message_id,
                "channel_id": channel_id,
                "key_epoch": key_epoch,
                "envelope_b64": b64e(envelope),
            },
        )

    def list_messages(self, channel_id: str, limit: int = 100) -> list[dict]:
        return self.request(
            "GET", f"/api/v2/channels/{channel_id}/messages", params={"limit": limit}
        )

    # -- fleet -----------------------------------------------------------------

    def heartbeat(self) -> dict:
        return self.request("POST", "/api/v2/fleet/heartbeat", json={})
