"""PRAHARI runtime configuration with fail-safe defaults."""
from __future__ import annotations

import os
import secrets
import sys
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_PLACEHOLDERS = {"", "secret", "changeme", "supersecretkey", "your_private_key_here"}

#: 32 characters is roughly the shortest a token_urlsafe secret can be while still
#: carrying enough entropy to be worth the name. Anything shorter in production is
#: refused outright rather than warned about.
MIN_JWT_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: str = Field(default="development")
    database_url: str = Field(
        default="postgresql+asyncpg://prahari:change-this-local-password@localhost:5432/prahari"
    )
    jwt_secret: str = Field(default="")
    jwt_algorithm: str = Field(default="HS256")
    access_token_ttl_minutes: int = Field(default=60)
    pqc_backend: str = Field(default="kyber-py")
    cors_origins: str = Field(default="http://localhost:5173,http://127.0.0.1:5173")

    rekey_after_messages: int = Field(default=100, ge=1)
    #: Raised from 15. A time-based rotation on a quiet channel spends a handshake on
    #: nobody's behalf: the message-count limit already bounds how much traffic one epoch
    #: covers, and this only bounds how long. An hour keeps the window short while cutting
    #: rotations roughly fourfold on a channel used in bursts.
    rekey_after_minutes: int = Field(default=60, ge=1)
    max_message_bytes: int = Field(default=131072, ge=1024)

    # Sized for the 1000-endpoint target. Every aircraft holds one long-lived WebSocket
    # plus short REST bursts, so concurrent *database* work is far below the endpoint
    # count; these defaults leave headroom without exhausting PostgreSQL's max_connections.
    #
    # Sized for a small shared host rather than for the ceiling. Each PostgreSQL backend
    # costs several megabytes whether or not it is busy, so a pool able to open 50 of them
    # is a few hundred megabytes this box does not have to spare. Raise on hardware that
    # warrants it.
    db_pool_size: int = Field(default=5, ge=1)
    db_max_overflow: int = Field(default=5, ge=0)
    db_pool_timeout_seconds: int = Field(default=30, ge=1)
    db_pool_recycle_seconds: int = Field(default=1800, ge=60)
    #: Upper bound on simultaneous WebSocket clients. 0 disables the limit. Every open
    #: socket holds kernel and application buffers, so this is a real memory ceiling.
    max_websocket_connections: int = Field(default=200, ge=0)

    #: WebAuthn relying party. `rp_id` must be the site's registrable domain (or a parent
    #: of it) and is what the authenticator binds a credential to; changing it invalidates
    #: every passkey already registered. Empty means "derive from the first allowed
    #: origin", which is right for development and explicit in production.
    webauthn_rp_id: str = Field(default="")
    webauthn_rp_name: str = Field(default="PRAHARI")

    #: Base64 ML-DSA-65 secret key used to sign anchor roots. Unset means batches are
    #: Merkle-verifiable but carry no attestation of origin, which is stated rather
    #: than hidden. Generate with app.crypto.pqsign.generate_keypair().
    anchor_pq_secret_key: str = Field(default="")
    anchor_pq_public_key: str = Field(default="")

    polygon_rpc_url: str = Field(default="")
    anchor_contract_address: str = Field(default="")
    anchor_private_key: str = Field(default="")

    qiskit_ibm_token: str = Field(default="")
    qiskit_ibm_instance: str = Field(default="")
    qiskit_ibm_channel: str = Field(default="ibm_quantum_platform")

    #: The quantum lab is a demonstration, and by far the most expensive thing this
    #: service can be asked to do. Left on by default so development and the test suite
    #: behave as before, and turned off automatically in production unless someone opts
    #: back in -- a teaching endpoint has no claim on the CPU of a box carrying live
    #: customer sites. Set `QUANTUM_LAB_ENABLED=true` to run it there anyway.
    quantum_lab_enabled_override: bool | None = Field(default=None, alias="QUANTUM_LAB_ENABLED")

    @field_validator("database_url")
    @classmethod
    def coerce_async_driver(cls, value: str) -> str:
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+asyncpg://", 1)
        if value.startswith("sqlite://") and "aiosqlite" not in value:
            return value.replace("sqlite://", "sqlite+aiosqlite://", 1)
        return value

    @property
    def is_production(self) -> bool:
        return self.environment.strip().lower() in {"production", "prod"}

    @property
    def quantum_lab_enabled(self) -> bool:
        if self.quantum_lab_enabled_override is not None:
            return self.quantum_lab_enabled_override
        return not self.is_production

    @property
    def webauthn_origins(self) -> list[str]:
        """Origins a passkey ceremony may come from.

        The CORS list, reused rather than duplicated: a second list of allowed origins is
        a second thing to forget to update, and the two would silently disagree the first
        time a domain moved.
        """
        return self.cors_origin_list

    @property
    def webauthn_relying_party(self) -> str:
        if self.webauthn_rp_id:
            return self.webauthn_rp_id
        # Derived from the first allowed origin: strip the scheme, then the port. An RP ID
        # is a bare domain -- "https://x.example:8443" is not one and the authenticator
        # would reject the ceremony rather than say why.
        first = next(iter(self.webauthn_origins), "")
        host = first.split("://", 1)[-1].split("/", 1)[0]
        return host.rsplit(":", 1)[0] if ":" in host else host

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    def validate_for_runtime(self) -> None:
        secret = self.jwt_secret.strip()
        if secret.lower() in INSECURE_PLACEHOLDERS:
            if self.is_production:
                raise RuntimeError("JWT_SECRET must be set to a strong random value in production")
            self.jwt_secret = secrets.token_urlsafe(48)
            print("[config] JWT_SECRET unset; using an ephemeral development secret.", file=sys.stderr)
        elif self.is_production and len(secret) < MIN_JWT_SECRET_LENGTH:
            # The placeholder list only catches secrets someone copied from the docs. A
            # short one they invented themselves is just as forgeable, and every session
            # token in the system rests on it.
            raise RuntimeError(
                f"JWT_SECRET must be at least {MIN_JWT_SECRET_LENGTH} characters in "
                "production; generate one with "
                "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
            )

        if self.is_production:
            # Previously a warning on stderr, which is exactly where a deployment note
            # goes to be ignored. The pure-Python ML-KEM is documented as research grade
            # and not constant-time, so in production this is a refusal, not advice.
            if self.pqc_backend != "liboqs":
                raise RuntimeError(
                    f"PQC_BACKEND={self.pqc_backend!r} is not constant-time and must not "
                    "be used in production. Set PQC_BACKEND=liboqs (see "
                    "requirements-hardened.txt), or set ENVIRONMENT=development if this "
                    "is a demo."
                )
            # Fail at startup rather than at the first handshake: a backend that cannot
            # import should stop a deploy, not surface as a runtime error for one user.
            from .crypto import pqc

            try:
                backend = pqc.get_backend()
            except pqc.PQCError as exc:
                raise RuntimeError(f"PQC_BACKEND=liboqs selected but unusable: {exc}") from exc
            print(f"[config] PQC backend: {backend.name}", file=sys.stderr)


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    os.environ.setdefault("PQC_BACKEND", settings.pqc_backend)
    settings.validate_for_runtime()
    return settings
