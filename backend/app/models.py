"""PRAHARI ORM models. Message content is always opaque ciphertext."""
from __future__ import annotations

import uuid

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from .database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


server_members = Table(
    "server_members",
    Base.metadata,
    Column("user_id", String, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("server_id", String, ForeignKey("servers.id", ondelete="CASCADE"), primary_key=True),
)

channel_members = Table(
    "channel_members",
    Base.metadata,
    Column("user_id", String, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("channel_id", String, ForeignKey("channels.id", ondelete="CASCADE"), primary_key=True),
)


#: A peer is either a human operator or an unmanned endpoint. Both hold their own
#: Ed25519/X25519/ML-KEM private keys and establish the *same* two-party hybrid session,
#: so nothing downstream of identity needs to know which kind it is talking to.
PEER_KINDS = ("human", "uav", "gcs")


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=_uuid)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String(16), nullable=False, default="member")
    status = Column(String(16), nullable=False, default="active")
    kind = Column(String(16), nullable=False, default="human", index=True)

    ed25519_public_key = Column(LargeBinary(32), nullable=False)
    key_verified = Column(Boolean, nullable=False, default=False)
    x25519_public_key = Column(LargeBinary(32), nullable=True)
    ml_kem_encapsulation_key = Column(LargeBinary(1184), nullable=True)
    key_bundle_signature = Column(LargeBinary(64), nullable=True)

    pending_challenge = Column(String, nullable=True)
    challenge_issued_at = Column(DateTime(timezone=True), nullable=True)

    #: TOTP shared secret. Present but not enabled means setup was started and never
    #: confirmed, which must not be treated as a second factor being in force.
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, nullable=False, default=False)

    #: Single-use WebAuthn ceremony challenge, base64url. Kept apart from
    #: `pending_challenge` above, which belongs to key publication: one flow clearing the
    #: other's nonce would produce failures that look like tampering and are not.
    webauthn_challenge = Column(String, nullable=True)
    webauthn_challenge_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)

    servers = relationship("Server", secondary=server_members, back_populates="members")
    channels = relationship("Channel", secondary=channel_members, back_populates="members")


class Session(Base):
    """One issued access token, so it can be listed and taken away.

    A JWT validates itself from its signature, which is exactly why revocation needs a
    record on this side: without one, a token that leaks stays good until it expires and
    nothing can intervene. The row is keyed by the token's own `jti`, so presenting a
    token is enough to find its session.

    Rows are marked revoked rather than deleted. A missing row means "not a session this
    server issued" and is refused, so deletion would quietly become a second way to be
    logged out — and would lose the record of when a session was ended, which is the part
    worth auditing.
    """

    __tablename__ = "sessions"

    #: The `jti` claim of the token this row represents.
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    #: `human` or `uav` — an aircraft renewing its credentials creates sessions too, and
    #: showing them next to browser sign-ins would be noise rather than information.
    kind = Column(String(16), nullable=False, default="human")
    user_agent = Column(String(256), nullable=True)
    ip_address = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)


class Server(Base):
    __tablename__ = "servers"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String(96), nullable=False)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    #: Set when the workspace is deleted. The rows stay for a grace period so an accidental
    #: deletion -- which reaches other people's history, not just the owner's -- is
    #: recoverable rather than final the instant the button is pressed. Access is refused
    #: from the moment this is set; only the ability to undo survives.
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    members = relationship("User", secondary=server_members, back_populates="servers")
    channels = relationship("Channel", back_populates="server", cascade="all, delete-orphan")


class Channel(Base):
    __tablename__ = "channels"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String(96), nullable=False)
    server_id = Column(String, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)
    key_epoch = Column(Integer, nullable=False, default=0)
    epoch_started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    #: Which member drives the ratchet. NULL keeps the historical rule -- lowest username
    #: wins -- which is fine when either side may speak first.
    #:
    #: It is not fine for the aircraft link. A Double Ratchet responder cannot send until
    #: it has received, and an aircraft's first act is to stream telemetry upward, not to
    #: wait for a command. So the link channel names the aircraft explicitly: the side
    #: that transmits first has to be the side that opens the ratchet.
    initiator_id = Column(String, ForeignKey("users.id"), nullable=True)

    server = relationship("Server", back_populates="channels")
    members = relationship("User", secondary=channel_members, back_populates="channels")
    messages = relationship("Message", back_populates="channel", cascade="all, delete-orphan")


class SessionOffer(Base):
    """One member's copy of a channel's key material for one epoch.

    Two shapes share this table, distinguished by `wrapped_group_key`:

    - **Two-party (NULL).** The hybrid KEM output *is* the session key, and it seeds a
      Double Ratchet. One offer per epoch, initiator to responder. Unchanged.
    - **Group (non-NULL).** The initiator draws one random group key for the epoch and
      seals it separately to every other member, so there is one row per recipient. The
      KEM output is a *wrapping* key here, never the message key.

    Hence the uniqueness rule is per recipient rather than per epoch. Widening it is what
    lets a channel hold more than two people at all -- the old
    `unique(channel_id, key_epoch)` physically permitted exactly one recipient.
    """

    __tablename__ = "session_offers"
    __table_args__ = (
        UniqueConstraint(
            "channel_id", "key_epoch", "responder_id", name="uq_channel_epoch_responder_offer"
        ),
    )

    id = Column(String, primary_key=True, default=_uuid)
    channel_id = Column(String, ForeignKey("channels.id", ondelete="CASCADE"), nullable=False, index=True)
    key_epoch = Column(Integer, nullable=False)
    initiator_id = Column(String, ForeignKey("users.id"), nullable=False)
    responder_id = Column(String, ForeignKey("users.id"), nullable=False)
    x25519_ephemeral_public = Column(LargeBinary(32), nullable=False)
    ml_kem_ciphertext = Column(LargeBinary(1088), nullable=False)
    offer_signature = Column(LargeBinary(64), nullable=False)
    #: AES-GCM of the epoch's group key under the KEM-derived wrapping key. NULL for
    #: two-party channels, where no group key exists to wrap.
    wrapped_group_key = Column(LargeBinary, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AnchorBatch(Base):
    __tablename__ = "anchor_batches"

    id = Column(String, primary_key=True, default=_uuid)
    merkle_root = Column(LargeBinary(32), nullable=False, unique=True)
    leaf_count = Column(Integer, nullable=False)
    chain_tx_hash = Column(String, nullable=True)
    #: ML-DSA signature over the root, when an anchor signing key is configured. Optional
    #: for the same reason Polygon anchoring is: it needs a secret this box may not hold.
    pq_signature = Column(LargeBinary, nullable=True)
    pq_algorithm = Column(String(32), nullable=True)
    status = Column(String(32), nullable=False, default="local_verified")
    confirmed = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class UavProfile(Base):
    """Non-secret registry data for an unmanned endpoint.

    Deliberately holds no key material: the UAV's private keys live on the aircraft, and
    its telemetry travels as opaque AES-GCM envelopes like any other message. What the
    server learns here is the same class of metadata it already learns about human
    accounts -- an identifier, an owner, and liveness -- as recorded in the threat model.
    """

    __tablename__ = "uav_profiles"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(
        String, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True
    )
    operator_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    callsign = Column(String(64), unique=True, nullable=False, index=True)
    airframe = Column(String(96), nullable=True)
    fleet = Column(String(96), nullable=False, default="default", index=True)

    #: Single-use provisioning secret, stored only as a hash. Cleared on enrolment.
    enrollment_token_hash = Column(String, nullable=True)
    enrolled_at = Column(DateTime(timezone=True), nullable=True)

    #: Containment state: NULL/"active", "quarantined" (reversible) or "revoked" (final).
    #: Nullable with NULL meaning active, following `users.totp_enabled` -- the additive
    #: column reconciler in database.py cannot add a NOT NULL column to a populated table.
    #:
    #: This is the fleet-facing record of *why* and *when*. Enforcement lives on
    #: `users.status`, which the device token and link paths already gate on, so there is
    #: one place a request is actually refused rather than two that can disagree.
    security_state = Column(String(16), nullable=True, index=True)
    security_state_at = Column(DateTime(timezone=True), nullable=True)
    security_state_reason = Column(String(256), nullable=True)

    #: Remote attestation. `expected_measurement` is the firmware/boot digest the operator
    #: pins; `last_measurement` is what the aircraft reported on its most recent heartbeat.
    #: Comparing them detects drift -- a downgrade, a mis-flashed image, an unapproved
    #: build. It cannot detect a compromise sophisticated enough to report the digest it
    #: knows the operator expects; see the note on the attestation endpoint.
    #:
    #: Pinned by the operator rather than trust-on-first-use: TOFU against an endpoint that
    #: was already compromised pins the attacker's firmware as the good one.
    expected_measurement = Column(LargeBinary(32), nullable=True)
    last_measurement = Column(LargeBinary(32), nullable=True)
    last_measurement_at = Column(DateTime(timezone=True), nullable=True)

    #: Device re-authentication nonce. An aircraft holds no password, so it proves its
    #: identity by signing a fresh challenge with the Ed25519 key bound at enrolment.
    #: Kept separate from User.pending_challenge so key publication and token renewal
    #: cannot clobber each other.
    auth_challenge = Column(String, nullable=True)
    auth_challenge_issued_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_at = Column(DateTime(timezone=True), nullable=True, index=True)

    #: Dedicated two-party channel carrying the encrypted C2/telemetry link.
    link_channel_id = Column(
        String, ForeignKey("channels.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        # Hot path for both chat history and telemetry replay:
        # WHERE channel_id = ? ORDER BY created_at DESC LIMIT n
        Index("ix_messages_channel_created", "channel_id", "created_at"),
        # Anchor batching scans unanchored messages in a stable total order.
        Index("ix_messages_batch_created_id", "anchor_batch_id", "created_at", "id"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    client_message_id = Column(String(64), unique=True, nullable=False, index=True)
    sender_id = Column(String, ForeignKey("users.id"), nullable=False)
    channel_id = Column(String, ForeignKey("channels.id", ondelete="CASCADE"), nullable=False)
    envelope = Column(LargeBinary, nullable=False)
    key_epoch = Column(Integer, nullable=False)
    content_hash = Column(LargeBinary(32), nullable=False)
    anchor_batch_id = Column(String, ForeignKey("anchor_batches.id"), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    #: Set when the author retracts the message. The row survives with an emptied
    #: `envelope` and an untouched `content_hash`: the hash is a leaf in an anchor batch's
    #: Merkle tree, so deleting or recomputing it would invalidate every proof already
    #: published for that batch. Retraction removes the content, not the evidence that
    #: something occupied that position.
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    channel = relationship("Channel", back_populates="messages")


class Invite(Base):
    """A shareable link that admits one or more peers to a workspace.

    Only the SHA-256 of the code is stored, following the same rule as
    `UavProfile.enrollment_token_hash`: a database disclosure must not hand an attacker a
    working invite. The plaintext code is returned exactly once, at creation. Listing an
    invite afterwards shows its usage and expiry but never the code -- if the creator
    loses it they mint a new one.

    An invite grants *membership*, never key material. Someone who redeems a stolen code
    joins the workspace but still cannot read any message: plaintext requires the
    two-party hybrid handshake against a published, signed key bundle.
    """

    __tablename__ = "invites"

    id = Column(String, primary_key=True, default=_uuid)
    code_hash = Column(String(64), unique=True, nullable=False, index=True)
    #: Non-secret leading characters, so the creator can tell two live invites apart.
    code_hint = Column(String(8), nullable=False)
    server_id = Column(String, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    label = Column(String(96), nullable=True)
    max_uses = Column(Integer, nullable=False, default=1)
    use_count = Column(Integer, nullable=False, default=0)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class LinkRequest(Base):
    """A request from one operator to open an encrypted link with another.

    Deliberately two-sided: the target must accept before a channel exists. Nobody can
    force a session onto a peer who has not agreed to it, which keeps the consent model
    the same as the aircraft link, where enrolment is an explicit act.
    """

    __tablename__ = "link_requests"
    __table_args__ = (
        # At most one live request per direction. Settled rows are free to accumulate as
        # history, so the constraint covers only the pending state.
        Index(
            "uq_link_request_pending",
            "requester_id",
            "target_id",
            unique=True,
            sqlite_where=text("status = 'pending'"),
            postgresql_where=text("status = 'pending'"),
        ),
    )

    id = Column(String, primary_key=True, default=_uuid)
    requester_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(16), nullable=False, default="pending", index=True)
    note = Column(String(200), nullable=True)
    #: Set when accepted: the two-party channel opened for this pair.
    channel_id = Column(String, ForeignKey("channels.id", ondelete="SET NULL"), nullable=True)
    server_id = Column(String, ForeignKey("servers.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    responded_at = Column(DateTime(timezone=True), nullable=True)


class MessageReceipt(Base):
    """Per-recipient delivery and read state.

    Metadata only. The server already knows who is in a channel and when a message
    arrived, so recording that a recipient fetched or displayed it reveals nothing the
    threat model did not already grant it -- and still nothing about content.
    """

    __tablename__ = "message_receipts"
    __table_args__ = (
        UniqueConstraint("message_id", "user_id", name="uq_receipt_message_user"),
        Index("ix_receipts_user_message", "user_id", "message_id"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    message_id = Column(String, ForeignKey("messages.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    channel_id = Column(String, ForeignKey("channels.id", ondelete="CASCADE"), nullable=False, index=True)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    read_at = Column(DateTime(timezone=True), nullable=True)


class Certificate(Base):
    """A hybrid certificate: one body, signed by the issuer with Ed25519 *and* ML-DSA.

    Both signatures are required to verify. Accepting either would leave the chain as
    strong as whichever algorithm breaks first, since an attacker chooses which to forge --
    see app/pki.py.

    The private halves are never here. This table holds bodies, public keys and signatures;
    certificates arrive already signed and are re-verified before being stored. A server
    able to issue one could impersonate everyone the chain vouches for, which is the whole
    authority this design keeps out of reach.
    """

    __tablename__ = "certificates"
    __table_args__ = (
        UniqueConstraint("serial", name="uq_certificate_serial"),
        Index("ix_certificates_issuer", "issuer_serial"),
        Index("ix_certificates_subject", "subject_id"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    serial = Column(String(64), nullable=False)
    #: Equal to `serial` for a self-issued root; that identity is what terminates a chain.
    issuer_serial = Column(String(64), nullable=False)

    subject_id = Column(String, nullable=False)
    subject_name = Column(String(128), nullable=False)
    #: Whether this certificate may issue others. Enforced during chain walking, so a leaf
    #: cannot be pressed into service as an issuer.
    is_ca = Column(Boolean, nullable=False, default=False)

    ed25519_public_key = Column(LargeBinary(32), nullable=False)
    #: ML-DSA-65 public key. Roughly 2 KB — larger than everything else in the row, and the
    #: reason certificates are fetched by serial rather than listed in bulk by default.
    mldsa_public_key = Column(LargeBinary, nullable=False)

    ed25519_signature = Column(LargeBinary(64), nullable=False)
    mldsa_signature = Column(LargeBinary, nullable=False)

    not_before = Column(DateTime(timezone=True), nullable=False)
    not_after = Column(DateTime(timezone=True), nullable=False)

    #: Pinned roots only. A self-signed certificate proves nothing on its own, so a root is
    #: trusted because an administrator said so, never because it arrived.
    trusted_root = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(256), nullable=True)

    submitted_by = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class FirmwareRelease(Base):
    """A firmware image an operator has approved for a fleet.

    The image itself is not here. This deployment shares two cores and a disk with the
    operator's other services, and firmware is measured in tens of megabytes per release --
    storing and serving it would be the single largest thing this service does, for no
    security benefit. What is stored is the part that carries trust: the digest, and an
    Ed25519 signature over it made with the operator's identity key.

    That signature is why the image can live anywhere. An endpoint fetches the bytes from
    whatever mirror is convenient, hashes them, and checks the digest against this signed
    record before it will install. A hostile mirror can serve the wrong bytes; it cannot
    make them verify.
    """

    __tablename__ = "firmware_releases"
    __table_args__ = (
        UniqueConstraint("fleet", "version", name="uq_firmware_fleet_version"),
        Index("ix_firmware_fleet_created", "fleet", "created_at"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    operator_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    fleet = Column(String(96), nullable=False)
    version = Column(String(64), nullable=False)

    #: SHA-256 of the image. The same value an endpoint reports as its measurement, which
    #: is what lets attestation and update share one notion of "which firmware".
    measurement = Column(LargeBinary(32), nullable=False)
    #: Where the bytes can be fetched. Untrusted by design -- see the class docstring.
    image_url = Column(String(512), nullable=True)
    size_bytes = Column(Integer, nullable=True)

    #: Ed25519 over the release payload, by the operator's identity key. This is the whole
    #: trust anchor: an endpoint that holds the operator's public key can verify a release
    #: without trusting the server that served it.
    signature = Column(LargeBinary(64), nullable=False)

    #: Set when a release is withdrawn -- a bad build, or one found vulnerable. Endpoints
    #: refuse to install a withdrawn release even if they already fetched the record.
    withdrawn_at = Column(DateTime(timezone=True), nullable=True)
    withdrawn_reason = Column(String(256), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class VpnGateway(Base):
    """A tunnel endpoint this deployment issues configuration for.

    PRAHARI is the *control plane* only: it registers who may join, hands out addresses,
    carries sealed key material between peers, and revokes access. It does not terminate
    tunnels. That is not a simplification -- a data plane is a sustained CPU and interrupt
    cost, and this service runs on two shared cores alongside the operator's other sites.
    Packets belong on a box whose job is packets.

    The gateway holds an ordinary account (`user_id`) so it can publish an X25519 +
    ML-KEM-768 bundle like any other peer. That is what makes the "quantum" part real
    rather than decorative: pre-shared keys are sealed *to that bundle* by the enrolling
    peer, so the material that gives WireGuard its post-quantum resistance is protected by
    the same hybrid KEM used everywhere else here -- and never travels in a form this
    server can read.
    """

    __tablename__ = "vpn_gateways"
    __table_args__ = (UniqueConstraint("owner_id", "name", name="uq_vpn_gateway_owner_name"),)

    id = Column(String, primary_key=True, default=_uuid)
    owner_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    #: The gateway's own account, whose published key bundle peers seal PSKs to.
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(64), nullable=False)

    #: WireGuard public key, base64. Public by definition; the private half never leaves
    #: the gateway, and this service has no use for it.
    wg_public_key = Column(String(64), nullable=False)
    #: host:port peers dial. Not secret -- it is in every client config.
    endpoint = Column(String(255), nullable=False)
    #: Tunnel subnet, e.g. "10.99.0.0/24".
    network_cidr = Column(String(64), nullable=False)
    #: Next host number to hand out. A counter rather than a scan for the lowest free
    #: address: allocation stays O(1) as the peer list grows, which matters far more than
    #: reclaiming the gaps a revoked peer leaves behind.
    next_host = Column(Integer, nullable=False, default=2)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class VpnPeer(Base):
    """One device's membership of a gateway.

    Everything stored here is either public or opaque. The peer generates its own
    WireGuard key pair and its own pre-shared key locally, seals the PSK to the gateway's
    hybrid bundle, and sends this service the public key and the sealed blob. So a full
    disclosure of this table yields public keys, addresses, and ciphertext nobody here can
    open -- the same standard the message tables are held to.
    """

    __tablename__ = "vpn_peers"
    __table_args__ = (
        UniqueConstraint("gateway_id", "wg_public_key", name="uq_vpn_peer_gateway_key"),
        UniqueConstraint("gateway_id", "assigned_ip", name="uq_vpn_peer_gateway_ip"),
        Index("ix_vpn_peers_gateway_status", "gateway_id", "status"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    gateway_id = Column(String, ForeignKey("vpn_gateways.id", ondelete="CASCADE"), nullable=False)
    owner_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(64), nullable=False)

    wg_public_key = Column(String(64), nullable=False)
    assigned_ip = Column(String(64), nullable=False)
    #: The pre-shared key, sealed to the gateway's hybrid bundle by the peer. Opaque here.
    sealed_psk = Column(LargeBinary, nullable=False)

    status = Column(String(16), nullable=False, default="active", index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(256), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class PasskeyCredential(Base):
    """One registered WebAuthn credential.

    Only public material is stored: a credential id and an SPKI public key. Nothing here
    lets the server authenticate as the user, and losing this table costs a factor rather
    than an account.

    It is deliberately a *second* factor and never a recovery path. The credential
    hierarchy this system settled on puts the identity key above everything, because that
    key is what decrypts the messages a second factor exists to protect and is the only
    way back from a lost authenticator. A passkey that could block the identity-key reset
    would strand a user who lost their device behind a device they no longer have.
    """

    __tablename__ = "passkey_credentials"
    __table_args__ = (
        UniqueConstraint("credential_id", name="uq_passkey_credential_id"),
        Index("ix_passkeys_user", "user_id"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    #: Raw credential id as issued by the authenticator.
    credential_id = Column(LargeBinary, nullable=False)
    #: The credential public key, SPKI DER, straight from the browser's getPublicKey().
    public_key = Column(LargeBinary, nullable=False)
    #: Authenticator's signature counter. Monotonic where implemented; zero where not.
    sign_count = Column(Integer, nullable=False, default=0)
    label = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)


class KeyBundleRecord(Base):
    """Every key bundle a user has ever published, in the order they published them.

    The account row holds only the *current* bundle, which is what a session needs. That
    made a key change indistinguishable from a key that had always been that value: a
    relay could serve a different bundle and the only defence was two people reading
    safety numbers aloud to each other.

    This table is append-only. Each row carries the hash of the row before it for the same
    user, so the sequence cannot be reordered, shortened, or edited after the fact without
    breaking every hash that follows. A relay can still decline to show you a row -- no
    log prevents silence -- but it can no longer rewrite history and have the record agree
    with it.

    Chained per user rather than globally, deliberately. A global chain would make two
    unrelated people publishing at the same moment contend for the same tail, and a
    failure there would reject a legitimate publish for no security benefit. One person
    publishing twice concurrently is a client bug, and the unique constraint says so.
    """

    __tablename__ = "key_bundle_records"
    __table_args__ = (
        UniqueConstraint("user_id", "seq", name="uq_key_record_user_seq"),
        Index("ix_key_records_user_seq", "user_id", "seq"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    #: 1 for the first bundle this account published, incrementing thereafter.
    seq = Column(Integer, nullable=False)

    ed25519_public_key = Column(LargeBinary(32), nullable=False)
    x25519_public_key = Column(LargeBinary(32), nullable=False)
    ml_kem_encapsulation_key = Column(LargeBinary, nullable=False)
    #: The user's own Ed25519 signature over the bundle. The relay cannot produce this,
    #: which is why it can withhold a row but never fabricate one.
    bundle_signature = Column(LargeBinary(64), nullable=False)

    #: NULL on the first row; otherwise the previous row's `entry_hash` for this user.
    prev_hash = Column(LargeBinary(32), nullable=True)
    entry_hash = Column(LargeBinary(32), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=_uuid)
    actor_id = Column(String, nullable=True, index=True)
    event = Column(String(96), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default="low")
    source_ip = Column(String, nullable=True)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    #: Tamper-evidence, filled in by sealing rather than on write. NULL means "written but
    #: not yet sealed" -- see app/audit_chain.py for why the chain is not built on the hot
    #: path. Nullable is also what lets the additive-column reconciler add these to a table
    #: that already has rows.
    seq = Column(Integer, nullable=True, index=True)
    prev_hash = Column(LargeBinary(32), nullable=True)
    entry_hash = Column(LargeBinary(32), nullable=True)


class AuditCheckpoint(Base):
    """The head of the sealed audit chain at a point in time.

    Sealing alone proves the sealed rows have not been edited, but not that rows were never
    *removed before they were ever sealed*. A checkpoint is the commitment that closes the
    difference: it records how many entries existed and what the head hash was, so a later
    log that is shorter, or whose head differs at the same sequence, is provably not the
    same log. Checkpoints are the thing worth copying somewhere the server cannot reach.
    """

    __tablename__ = "audit_checkpoints"

    id = Column(String, primary_key=True, default=_uuid)
    #: Sequence of the last entry covered by this checkpoint.
    seq = Column(Integer, nullable=False, index=True)
    head_hash = Column(LargeBinary(32), nullable=False)
    entry_count = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class QuantumExperiment(Base):
    __tablename__ = "quantum_experiments"

    id = Column(String, primary_key=True, default=_uuid)
    actor_id = Column(String, ForeignKey("users.id"), nullable=False)
    backend = Column(String(96), nullable=False)
    algorithm = Column(String(96), nullable=False)
    shots = Column(Integer, nullable=False)
    observed_bias = Column(String, nullable=True)
    qber = Column(String, nullable=True)
    passed = Column(Boolean, nullable=False)
    result_json = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
