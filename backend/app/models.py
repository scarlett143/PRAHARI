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
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)

    servers = relationship("Server", secondary=server_members, back_populates="members")
    channels = relationship("Channel", secondary=channel_members, back_populates="members")


class Server(Base):
    __tablename__ = "servers"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String(96), nullable=False)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

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

    server = relationship("Server", back_populates="channels")
    members = relationship("User", secondary=channel_members, back_populates="channels")
    messages = relationship("Message", back_populates="channel", cascade="all, delete-orphan")


class SessionOffer(Base):
    __tablename__ = "session_offers"
    __table_args__ = (UniqueConstraint("channel_id", "key_epoch", name="uq_channel_epoch_offer"),)

    id = Column(String, primary_key=True, default=_uuid)
    channel_id = Column(String, ForeignKey("channels.id", ondelete="CASCADE"), nullable=False, index=True)
    key_epoch = Column(Integer, nullable=False)
    initiator_id = Column(String, ForeignKey("users.id"), nullable=False)
    responder_id = Column(String, ForeignKey("users.id"), nullable=False)
    x25519_ephemeral_public = Column(LargeBinary(32), nullable=False)
    ml_kem_ciphertext = Column(LargeBinary(1088), nullable=False)
    offer_signature = Column(LargeBinary(64), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AnchorBatch(Base):
    __tablename__ = "anchor_batches"

    id = Column(String, primary_key=True, default=_uuid)
    merkle_root = Column(LargeBinary(32), nullable=False, unique=True)
    leaf_count = Column(Integer, nullable=False)
    chain_tx_hash = Column(String, nullable=True)
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


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=_uuid)
    actor_id = Column(String, nullable=True, index=True)
    event = Column(String(96), nullable=False, index=True)
    severity = Column(String(16), nullable=False, default="low")
    source_ip = Column(String, nullable=True)
    detail = Column(Text, nullable=True)
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
