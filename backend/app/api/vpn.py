"""Post-quantum VPN control plane.

WHAT THIS IS. Enrolment, addressing, sealed key distribution and revocation for WireGuard
tunnels. PRAHARI decides who may join and carries the material that lets them; it does not
carry packets.

WHY IT STOPS THERE. Terminating tunnels is a sustained CPU and interrupt cost, and this
service shares two cores with the operator's panel, billing and status sites. A data plane
here would be the most reliable way to take those down. Running WireGuard on a host whose
job is packets costs this deployment nothing and is faster besides -- the kernel module
does in a syscall what a Python process would do in a scheduler.

WHERE THE POST-QUANTUM PART ACTUALLY IS. WireGuard's handshake is X25519, which a
cryptanalytically relevant quantum computer would break. It also accepts a 32-byte
pre-shared key mixed into that handshake, and a tunnel whose PSK the attacker does not
have stays secure even if the X25519 half falls. So the PSK is the thing that must not
travel in the clear -- and here it never does: the enrolling peer generates it, seals it
to the gateway's published X25519 + ML-KEM-768 bundle with the same hybrid KEM the
messaging layer uses, and this service stores an opaque blob.

That is the whole claim, and it is worth stating narrowly. This does not make WireGuard
post-quantum. It distributes the one input that gives WireGuard post-quantum resistance,
over a channel that already has it, without the control plane ever being able to read it.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..database import get_db
from ..models import User, VpnGateway, VpnPeer
from ..security import CurrentUser
from .common import audit, b64d, b64e

router = APIRouter(prefix="/api/v2/vpn", tags=["vpn"])

ACTIVE = "active"
REVOKED = "revoked"

#: A WireGuard key is 32 bytes, which is 44 base64 characters including padding.
WG_KEY_CHARS = 44
#: Sealed PSK: an X25519 ephemeral (32) + ML-KEM-768 ciphertext (1088) + AEAD-wrapped
#: 32-byte key. Bounded so an enrolment cannot be used to store arbitrary data here.
MAX_SEALED_PSK = 4096


def _validate_wg_key(value: str, field: str) -> str:
    raw = b64d(value, expect=32, field=field)
    return b64e(raw)


async def _owned_gateway(db: AsyncSession, gateway_id: str, user: User) -> VpnGateway:
    gateway = (
        await db.execute(
            select(VpnGateway).where(
                VpnGateway.id == gateway_id, VpnGateway.owner_id == user.id
            )
        )
    ).scalars().first()
    if gateway is None:
        raise HTTPException(404, "no such gateway")
    return gateway


# -- gateways ----------------------------------------------------------------


class CreateGatewayRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    #: The account whose published hybrid bundle peers seal PSKs to. Usually an endpoint
    #: account provisioned for the gateway itself.
    gateway_username: str = Field(min_length=1, max_length=64)
    wg_public_key: str = Field(min_length=1, max_length=128)
    endpoint: str = Field(min_length=3, max_length=255)
    network_cidr: str = Field(default="10.99.0.0/24", max_length=64)


@router.post("/gateways")
async def create_gateway(
    body: CreateGatewayRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    try:
        network = ipaddress.ip_network(body.network_cidr, strict=True)
    except ValueError:
        raise HTTPException(400, "network_cidr is not a valid network") from None
    # /31 and /32 hold no usable hosts once the network and gateway addresses are taken,
    # and a peer would be handed an address it could never use.
    if network.num_addresses < 4:
        raise HTTPException(400, "network_cidr is too small to hold any peers")

    account = (
        await db.execute(select(User).where(User.username == body.gateway_username))
    ).scalars().first()
    if account is None:
        raise HTTPException(404, "no such gateway account")
    if not account.key_verified:
        # Without a published bundle there is nothing for peers to seal a PSK to, and the
        # tunnel would fall back to plain X25519 -- exactly what this exists to avoid.
        raise HTTPException(409, "the gateway account has not published a key bundle")

    gateway = VpnGateway(
        owner_id=user.id,
        user_id=account.id,
        name=body.name.strip(),
        wg_public_key=_validate_wg_key(body.wg_public_key, "wg_public_key"),
        endpoint=body.endpoint.strip(),
        network_cidr=str(network),
        next_host=2,  # .1 is the gateway itself.
    )
    db.add(gateway)
    await audit(
        db,
        event="vpn.gateway_created",
        actor_id=user.id,
        severity="medium",
        request=request,
        detail=f"name={gateway.name};cidr={gateway.network_cidr}",
    )
    await db.commit()
    await db.refresh(gateway)
    return _serialize_gateway(gateway, peer_count=0)


@router.get("/gateways")
async def list_gateways(user: CurrentUser, db: Annotated[AsyncSession, Depends(get_db)]):
    rows = (
        await db.execute(
            select(
                VpnGateway,
                select(func.count(VpnPeer.id))
                .where(VpnPeer.gateway_id == VpnGateway.id, VpnPeer.status == ACTIVE)
                .scalar_subquery(),
            )
            .where(VpnGateway.owner_id == user.id)
            .order_by(VpnGateway.name.asc())
        )
    ).all()
    return [_serialize_gateway(gateway, peer_count=count) for gateway, count in rows]


def _serialize_gateway(gateway: VpnGateway, *, peer_count: int) -> dict:
    return {
        "id": gateway.id,
        "name": gateway.name,
        "wg_public_key": gateway.wg_public_key,
        "endpoint": gateway.endpoint,
        "network_cidr": gateway.network_cidr,
        "gateway_address": str(ipaddress.ip_network(gateway.network_cidr).network_address + 1),
        "active_peers": int(peer_count or 0),
        "created_at": gateway.created_at,
    }


# -- peers -------------------------------------------------------------------


class EnrolPeerRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    wg_public_key: str = Field(min_length=1, max_length=128)
    #: The PSK, sealed to the gateway's hybrid bundle by the enrolling client.
    sealed_psk: str = Field(min_length=1, max_length=MAX_SEALED_PSK * 2)


@router.post("/gateways/{gateway_id}/peers")
async def enrol_peer(
    gateway_id: str,
    body: EnrolPeerRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Add a device to a gateway.

    The client has already done the parts that matter: generated a WireGuard key pair,
    generated a pre-shared key, and sealed that PSK to the gateway. What arrives here is a
    public key and a blob. Nothing in this handler can read the tunnel it is authorising.
    """
    gateway = await _owned_gateway(db, gateway_id, user)
    sealed = b64d(body.sealed_psk, field="sealed_psk")
    if len(sealed) > MAX_SEALED_PSK:
        raise HTTPException(413, "sealed_psk is too large")

    network = ipaddress.ip_network(gateway.network_cidr)
    address = _allocate(gateway, network)

    peer = VpnPeer(
        gateway_id=gateway.id,
        owner_id=user.id,
        name=body.name.strip(),
        wg_public_key=_validate_wg_key(body.wg_public_key, "wg_public_key"),
        assigned_ip=str(address),
        sealed_psk=sealed,
    )
    db.add(peer)
    await audit(
        db,
        event="vpn.peer_enrolled",
        actor_id=user.id,
        severity="medium",
        request=request,
        detail=f"gateway={gateway.name};peer={peer.name};ip={peer.assigned_ip}",
    )
    await db.commit()
    await db.refresh(peer)
    return _serialize_peer(peer, gateway)


def _allocate(gateway: VpnGateway, network) -> ipaddress._BaseAddress:
    """Hand out the next address, or refuse.

    Counter-based rather than a search for the lowest unused host: allocation stays
    constant-time however many peers exist. Addresses freed by revocation are not reused,
    which is a deliberate trade -- a recycled address makes an audit trail ambiguous about
    which device held it, and the space is large enough that it rarely matters.
    """
    usable = network.num_addresses - 2  # network and broadcast
    if gateway.next_host - 1 > usable:
        raise HTTPException(409, "this gateway's address range is exhausted")
    address = network.network_address + gateway.next_host
    if address not in network:
        raise HTTPException(409, "this gateway's address range is exhausted")
    gateway.next_host += 1
    return address


@router.get("/gateways/{gateway_id}/peers")
async def list_peers(
    gateway_id: str,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
    include_revoked: bool = False,
):
    """The peer list, as the gateway needs it to build its WireGuard configuration.

    Sealed PSKs are included: the gateway is the only party that can open them, and it has
    to, to complete a handshake. Revoked peers are omitted by default -- a gateway applying
    this list verbatim should end up denying them.
    """
    gateway = await _owned_gateway(db, gateway_id, user)
    conditions = [VpnPeer.gateway_id == gateway.id]
    if not include_revoked:
        conditions.append(VpnPeer.status == ACTIVE)

    peers = (
        await db.execute(
            select(VpnPeer).where(*conditions).order_by(VpnPeer.created_at.asc())
        )
    ).scalars().all()
    return {
        "gateway": _serialize_gateway(gateway, peer_count=len(peers)),
        "peers": [_serialize_peer(peer, gateway, with_psk=True) for peer in peers],
    }


def _serialize_peer(peer: VpnPeer, gateway: VpnGateway, *, with_psk: bool = False) -> dict:
    data = {
        "id": peer.id,
        "name": peer.name,
        "wg_public_key": peer.wg_public_key,
        "assigned_ip": peer.assigned_ip,
        "status": peer.status,
        "revoked_at": peer.revoked_at,
        "revocation_reason": peer.revocation_reason,
        "created_at": peer.created_at,
    }
    if with_psk:
        data["sealed_psk"] = b64e(peer.sealed_psk)
    return data


class RevokePeerRequest(BaseModel):
    reason: str = Field(default="", max_length=256)


@router.post("/peers/{peer_id}/revoke")
async def revoke_peer(
    peer_id: str,
    body: RevokePeerRequest,
    user: CurrentUser,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Remove a device's access.

    Say what this does and does not do, because the difference is where people get hurt.
    It removes the peer from the list the gateway builds its configuration from. It takes
    effect when the gateway next applies that configuration -- this service cannot reach
    into a running tunnel, and a session already established stays up until the gateway
    reloads. Pair it with a reload if the timing matters.
    """
    peer = (
        await db.execute(
            select(VpnPeer).where(VpnPeer.id == peer_id, VpnPeer.owner_id == user.id)
        )
    ).scalars().first()
    if peer is None:
        raise HTTPException(404, "no such peer")

    if peer.status != REVOKED:
        peer.status = REVOKED
        peer.revoked_at = datetime.now(timezone.utc)
        peer.revocation_reason = body.reason.strip() or None
        await audit(
            db,
            event="vpn.peer_revoked",
            actor_id=user.id,
            severity="high",
            request=request,
            detail=f"peer={peer.name};reason={body.reason.strip()[:120]}",
        )
        await db.commit()
        await db.refresh(peer)
    # Idempotent: revoking twice is a retry, not an error.
    return {"id": peer.id, "status": peer.status, "revoked_at": peer.revoked_at}


@router.get("/peers/{peer_id}/config")
async def peer_config(
    peer_id: str,
    user: CurrentUser,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Render the client-side WireGuard configuration for one peer.

    Two fields are deliberately left as placeholders rather than filled in: `PrivateKey`,
    which this service has never held, and `PresharedKey`, which it holds only sealed. The
    peer substitutes both from material it generated itself. A config this server could
    complete would be a config this server could use.
    """
    peer = (
        await db.execute(
            select(VpnPeer).where(VpnPeer.id == peer_id, VpnPeer.owner_id == user.id)
        )
    ).scalars().first()
    if peer is None:
        raise HTTPException(404, "no such peer")
    if peer.status != ACTIVE:
        raise HTTPException(409, "this peer is revoked")

    gateway = (
        await db.execute(select(VpnGateway).where(VpnGateway.id == peer.gateway_id))
    ).scalars().first()
    network = ipaddress.ip_network(gateway.network_cidr)

    config = "\n".join(
        [
            "[Interface]",
            "# Generated on this device; never sent to the control plane.",
            "PrivateKey = <your-private-key>",
            f"Address = {peer.assigned_ip}/{network.prefixlen}",
            "",
            "[Peer]",
            f"PublicKey = {gateway.wg_public_key}",
            "# Unseal from `sealed_psk` with your identity key before use.",
            "PresharedKey = <unsealed-preshared-key>",
            f"Endpoint = {gateway.endpoint}",
            f"AllowedIPs = {gateway.network_cidr}",
            "PersistentKeepalive = 25",
        ]
    )
    return {
        "peer": _serialize_peer(peer, gateway, with_psk=True),
        "config": config,
        "note": (
            "PrivateKey and PresharedKey are placeholders. The control plane holds neither "
            "in a form it can read."
        ),
    }
