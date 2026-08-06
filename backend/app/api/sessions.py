from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..crypto import pqc
from ..database import get_db
from ..models import SessionOffer
from ..realtime import manager
from .. import security
from ..security import CurrentUser
from .common import audit, b64d, b64e, channel_member_users, require_channel_member

router = APIRouter(prefix="/api/v2/sessions", tags=["sessions"])


class SessionOfferRequest(BaseModel):
    channel_id: str
    key_epoch: int
    responder_id: str
    x25519_ephemeral_public: str
    ml_kem_ciphertext: str
    offer_signature: str


@router.post("/offers")
async def create_offer(
    body: SessionOfferRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    channel = await require_channel_member(db, body.channel_id, user)
    if not user.key_verified:
        raise HTTPException(409, "initiator must publish a verified key bundle first")
    members = await channel_member_users(db, channel.id)
    if len(members) != 2:
        raise HTTPException(409, "hybrid session offers currently require exactly two channel members")
    if body.key_epoch != channel.key_epoch:
        raise HTTPException(409, "session offer epoch does not match channel epoch")

    sorted_members = sorted(members, key=lambda member: member.username.lower())
    # An explicit initiator on the channel wins over username order. The aircraft link
    # sets it, because the side that transmits first has to be the side that opens the
    # ratchet -- a ratchet responder cannot send until it has received. Both this check
    # and the one in GET /channels/{id} must agree, or a client would be told it is the
    # initiator and then refused when it published the offer.
    expected_initiator = next(
        (member for member in members if member.id == channel.initiator_id),
        sorted_members[0],
    )
    expected_responder = next(member for member in members if member.id != expected_initiator.id)
    if user.id != expected_initiator.id:
        raise HTTPException(409, f"{expected_initiator.username} is the deterministic session initiator")
    if body.responder_id != expected_responder.id:
        raise HTTPException(400, "responder does not match the other channel member")
    if not expected_responder.key_verified:
        raise HTTPException(409, "responder has no verified key bundle")

    ephemeral_public = b64d(
        body.x25519_ephemeral_public, expect=32, field="x25519_ephemeral_public"
    )
    kem_ciphertext = b64d(
        body.ml_kem_ciphertext, expect=pqc.CT_BYTES, field="ml_kem_ciphertext"
    )
    offer_signature = b64d(body.offer_signature, expect=64, field="offer_signature")

    existing = await _load_offer(db, channel.id, channel.key_epoch)
    if existing:
        return _existing_or_conflict(existing, ephemeral_public, kem_ciphertext)

    signed_payload = security.session_offer_signing_payload(
        channel_id=channel.id,
        key_epoch=channel.key_epoch,
        responder_id=expected_responder.id,
        x25519_ephemeral_public=ephemeral_public,
        ml_kem_ciphertext=kem_ciphertext,
    )
    if not security.verify_signature(
        ed25519_public_key=user.ed25519_public_key,
        message=signed_payload,
        signature=offer_signature,
    ):
        raise HTTPException(400, "session offer signature failed")

    offer = SessionOffer(
        channel_id=channel.id,
        key_epoch=channel.key_epoch,
        initiator_id=user.id,
        responder_id=expected_responder.id,
        x25519_ephemeral_public=ephemeral_public,
        ml_kem_ciphertext=kem_ciphertext,
        offer_signature=offer_signature,
    )
    db.add(offer)
    await audit(
        db,
        event="session.offer_created",
        actor_id=user.id,
        request=request,
        detail=f"{channel.id}:epoch={channel.key_epoch}",
    )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        existing = await _load_offer(db, channel.id, channel.key_epoch)
        if existing:
            return _existing_or_conflict(existing, ephemeral_public, kem_ciphertext)
        raise
    await db.refresh(offer)
    await manager.notify_users(
        [expected_responder.id],
        {"type": "session.offer_created", "channel_id": channel.id, "key_epoch": channel.key_epoch},
    )
    return _serialize(offer)


class GroupOfferEntry(BaseModel):
    responder_id: str
    x25519_ephemeral_public: str
    ml_kem_ciphertext: str
    offer_signature: str
    wrapped_group_key: str


class GroupOfferRequest(BaseModel):
    channel_id: str
    key_epoch: int
    offers: list[GroupOfferEntry]


@router.post("/offers/batch")
async def create_group_offers(
    body: GroupOfferRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Publish one sealed copy of the epoch's group key for every other member.

    The server stores and routes these; it cannot open any of them. Each entry is an
    independent hybrid encapsulation to one member's published bundle, wrapping the same
    group key, and each is signed by the initiator over its own recipient id -- so the
    relay can neither retarget a copy at a different member nor learn the key it carries.

    All-or-nothing on purpose: a partially published epoch would leave some members able
    to read the channel and others silently stuck, which is far harder to diagnose than a
    refusal.
    """
    channel = await require_channel_member(db, body.channel_id, user)
    if not user.key_verified:
        raise HTTPException(409, "initiator must publish a verified key bundle first")
    members = await channel_member_users(db, channel.id)
    if len(members) < 3:
        raise HTTPException(409, "two-party channels use POST /offers, which seeds a ratchet")
    if body.key_epoch != channel.key_epoch:
        raise HTTPException(409, "session offer epoch does not match channel epoch")

    sorted_members = sorted(members, key=lambda member: member.username.lower())
    expected_initiator = next(
        (member for member in members if member.id == channel.initiator_id),
        sorted_members[0],
    )
    if user.id != expected_initiator.id:
        raise HTTPException(409, f"{expected_initiator.username} is the deterministic session initiator")

    by_id = {member.id: member for member in members}
    # Every member, the initiator included. Sealing a copy to yourself is what lets you
    # read the group from a second browser: without it the one person who minted the key
    # is the only one who can never recover it, having no offer addressed to them. It
    # concedes nothing an attacker did not already have -- unwrapping still requires that
    # member's long-term private keys, exactly as it does for everyone else.
    expected_responders = {member.id for member in members}
    submitted = {entry.responder_id for entry in body.offers}
    if len(submitted) != len(body.offers):
        raise HTTPException(400, "duplicate responder in offer batch")
    if submitted != expected_responders:
        raise HTTPException(400, "offer batch must cover exactly the other channel members")
    for responder_id in expected_responders:
        if not by_id[responder_id].key_verified:
            raise HTTPException(409, f"{by_id[responder_id].username} has no verified key bundle")

    existing = await _load_offers(db, channel.id, channel.key_epoch)
    if existing:
        return _existing_batch_or_conflict(existing, body.offers)

    prepared = []
    for entry in body.offers:
        ephemeral_public = b64d(entry.x25519_ephemeral_public, expect=32, field="x25519_ephemeral_public")
        kem_ciphertext = b64d(entry.ml_kem_ciphertext, expect=pqc.CT_BYTES, field="ml_kem_ciphertext")
        offer_signature = b64d(entry.offer_signature, expect=64, field="offer_signature")
        wrapped = b64d(entry.wrapped_group_key, field="wrapped_group_key")
        if not 16 < len(wrapped) <= 128:
            raise HTTPException(400, "wrapped_group_key length is implausible for a wrapped 32-byte key")

        signed_payload = security.session_offer_signing_payload(
            channel_id=channel.id,
            key_epoch=channel.key_epoch,
            responder_id=entry.responder_id,
            x25519_ephemeral_public=ephemeral_public,
            ml_kem_ciphertext=kem_ciphertext,
            wrapped_group_key=wrapped,
        )
        if not security.verify_signature(
            ed25519_public_key=user.ed25519_public_key,
            message=signed_payload,
            signature=offer_signature,
        ):
            raise HTTPException(400, f"session offer signature failed for {by_id[entry.responder_id].username}")

        prepared.append(
            SessionOffer(
                channel_id=channel.id,
                key_epoch=channel.key_epoch,
                initiator_id=user.id,
                responder_id=entry.responder_id,
                x25519_ephemeral_public=ephemeral_public,
                ml_kem_ciphertext=kem_ciphertext,
                offer_signature=offer_signature,
                wrapped_group_key=wrapped,
            )
        )

    db.add_all(prepared)
    await audit(
        db,
        event="session.group_offers_created",
        actor_id=user.id,
        request=request,
        detail=f"{channel.id}:epoch={channel.key_epoch}:recipients={len(prepared)}",
    )
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        existing = await _load_offers(db, channel.id, channel.key_epoch)
        if existing:
            return _existing_batch_or_conflict(existing, body.offers)
        raise

    await manager.notify_users(
        sorted(expected_responders - {user.id}),
        {"type": "session.offer_created", "channel_id": channel.id, "key_epoch": channel.key_epoch},
    )
    return {"offers": [_serialize(offer) for offer in prepared]}


@router.get("/offers/{channel_id}")
async def get_offer(
    channel_id: str,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    epoch: int | None = None,
):
    """The offer addressed to the caller for this epoch.

    A group epoch holds one row per member, so this filters by recipient rather than
    returning "the" offer. For a two-party channel that is the same single row it always
    was -- the responder is the only member who was ever meant to read it.
    """
    channel = await require_channel_member(db, channel_id, user)
    target_epoch = channel.key_epoch if epoch is None else epoch
    offer = (
        await db.execute(
            select(SessionOffer).where(
                SessionOffer.channel_id == channel.id,
                SessionOffer.key_epoch == target_epoch,
                SessionOffer.responder_id == user.id,
            )
        )
    ).scalars().first()
    if offer is None:
        raise HTTPException(404, "session offer not found")
    return _serialize(offer)


async def _load_offers(db: AsyncSession, channel_id: str, key_epoch: int) -> list[SessionOffer]:
    return list(
        (
            await db.execute(
                select(SessionOffer).where(
                    SessionOffer.channel_id == channel_id,
                    SessionOffer.key_epoch == key_epoch,
                )
            )
        ).scalars().all()
    )


def _existing_batch_or_conflict(existing: list[SessionOffer], submitted: list) -> dict:
    """Return the stored batch only when it is byte-identical to the submitted one.

    Same reasoning as the two-party case: an epoch has exactly one set of offers. If a
    different batch is already published, the caller holds a group key nobody else
    derived, and every message it sends would fail authentication with no visible cause.
    Refuse and make them rotate to a fresh epoch instead.
    """
    by_responder = {offer.responder_id: offer for offer in existing}
    identical = len(existing) == len(submitted) and all(
        (stored := by_responder.get(entry.responder_id)) is not None
        and stored.x25519_ephemeral_public == b64d(entry.x25519_ephemeral_public)
        and stored.ml_kem_ciphertext == b64d(entry.ml_kem_ciphertext)
        and stored.wrapped_group_key == b64d(entry.wrapped_group_key)
        for entry in submitted
    )
    if identical:
        return {"offers": [_serialize(offer) for offer in existing]}
    raise HTTPException(
        409,
        detail={
            "code": "session_offer_exists",
            "message": (
                "a different group session is already published for this epoch; "
                "rotate the channel to the next epoch to establish a new one"
            ),
            "channel_id": existing[0].channel_id,
            "key_epoch": existing[0].key_epoch,
        },
    )


async def _load_offer(db: AsyncSession, channel_id: str, key_epoch: int) -> SessionOffer | None:
    return (
        await db.execute(
            select(SessionOffer).where(
                SessionOffer.channel_id == channel_id,
                SessionOffer.key_epoch == key_epoch,
            )
        )
    ).scalars().first()


def _existing_or_conflict(
    existing: SessionOffer, ephemeral_public: bytes, kem_ciphertext: bytes
) -> dict:
    """Return the stored offer only when it is byte-identical to the submitted one.

    An epoch has exactly one offer. Silently handing back a *different* stored offer
    would leave the initiator holding a session key derived from its own fresh
    ephemeral that no peer can reproduce, so every later message would fail
    authentication with no visible cause. Reject instead and make the client rotate.
    """
    if (
        existing.x25519_ephemeral_public == ephemeral_public
        and existing.ml_kem_ciphertext == kem_ciphertext
    ):
        return _serialize(existing)
    raise HTTPException(
        409,
        detail={
            "code": "session_offer_exists",
            "message": (
                "a different hybrid session offer is already published for this epoch; "
                "rotate the channel to the next epoch to establish a new session"
            ),
            "channel_id": existing.channel_id,
            "key_epoch": existing.key_epoch,
        },
    )


def _serialize(offer: SessionOffer) -> dict:
    return {
        "id": offer.id,
        "channel_id": offer.channel_id,
        "key_epoch": offer.key_epoch,
        "initiator_id": offer.initiator_id,
        "responder_id": offer.responder_id,
        "x25519_ephemeral_public": b64e(offer.x25519_ephemeral_public),
        "ml_kem_ciphertext": b64e(offer.ml_kem_ciphertext),
        "offer_signature": b64e(offer.offer_signature),
        # None on two-party channels, where the KEM output is the session key itself.
        "wrapped_group_key": b64e(offer.wrapped_group_key),
        "created_at": offer.created_at,
    }
