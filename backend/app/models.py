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
