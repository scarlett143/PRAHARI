"""VPN control plane.

The property that matters most is negative: at no point does this service hold anything
that would let it join or read a tunnel it authorised. These tests check that alongside
the ordinary behaviour -- addressing, revocation, ownership.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import base64
import secrets

from fastapi.testclient import TestClient

from app.main import app

from test_api_flow import register_verified
from test_fleet import _unique


def wg_key() -> str:
    """A WireGuard key is 32 bytes of base64; its contents are irrelevant here."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def sealed_psk() -> str:
    """Stands in for a PSK sealed to the gateway's hybrid bundle.

    Opaque to the server by construction, so a random blob exercises the same path the
    real thing does -- which is itself the point being tested.
    """
    return base64.b64encode(secrets.token_bytes(1152)).decode()


def _gateway(client: TestClient, headers, gateway_username: str, **overrides):
    body = {
        "name": overrides.pop("name", _unique("gw")),
        "gateway_username": gateway_username,
        "wg_public_key": overrides.pop("wg_public_key", wg_key()),
        "endpoint": overrides.pop("endpoint", "vpn.example:51820"),
        "network_cidr": overrides.pop("network_cidr", "10.99.0.0/24"),
    }
    return client.post("/api/v2/vpn/gateways", headers=headers, json=body)


def _enrol(client: TestClient, headers, gateway_id: str, name: str = "laptop"):
    return client.post(
        f"/api/v2/vpn/gateways/{gateway_id}/peers",
        headers=headers,
        json={"name": name, "wg_public_key": wg_key(), "sealed_psk": sealed_psk()},
    )


def test_a_gateway_issues_addresses_in_order():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("op"))
        gw_username = _unique("gwacct")
        register_verified(client, gw_username)

        created = _gateway(client, operator_headers, gw_username)
        assert created.status_code == 200, created.text
        gateway = created.json()
        assert gateway["gateway_address"] == "10.99.0.1"
        assert gateway["active_peers"] == 0

        first = _enrol(client, operator_headers, gateway["id"], "laptop").json()
        second = _enrol(client, operator_headers, gateway["id"], "phone").json()

        assert first["assigned_ip"] == "10.99.0.2"
        assert second["assigned_ip"] == "10.99.0.3"
        assert first["status"] == "active"


def test_the_control_plane_never_holds_usable_tunnel_material():
    """The whole design, in one assertion.

    A rendered config must carry no private key and no usable pre-shared key. If this ever
    fails, the server has become able to join the tunnels it hands out.
    """
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("op"))
        gw_username = _unique("gwacct")
        register_verified(client, gw_username)
        gateway = _gateway(client, operator_headers, gw_username).json()
        peer = _enrol(client, operator_headers, gateway["id"]).json()

        rendered = client.get(f"/api/v2/vpn/peers/{peer['id']}/config", headers=operator_headers)
        assert rendered.status_code == 200, rendered.text
        config = rendered.json()["config"]

        assert "PrivateKey = <your-private-key>" in config
        assert "PresharedKey = <unsealed-preshared-key>" in config
        assert peer["assigned_ip"] in config
        assert gateway["wg_public_key"] in config


def test_a_gateway_without_a_published_bundle_is_refused():
    """Otherwise a peer has nothing to seal a PSK to and the tunnel silently loses its
    post-quantum resistance -- the one thing this feature exists to provide."""
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("op"))

        unverified = _unique("bare")
        client.post(
            "/api/v2/auth/register",
            json={
                "username": unverified,
                "password": "correct-horse-battery-staple",
                "ed25519_public_key": base64.b64encode(secrets.token_bytes(32)).decode(),
            },
        )

        refused = _gateway(client, operator_headers, unverified)
        assert refused.status_code == 409


def test_revoking_a_peer_drops_it_from_the_gateway_list():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("op"))
        gw_username = _unique("gwacct")
        register_verified(client, gw_username)
        gateway = _gateway(client, operator_headers, gw_username).json()

        kept = _enrol(client, operator_headers, gateway["id"], "kept").json()
        gone = _enrol(client, operator_headers, gateway["id"], "gone").json()

        revoked = client.post(
            f"/api/v2/vpn/peers/{gone['id']}/revoke",
            headers=operator_headers,
            json={"reason": "device lost"},
        )
        assert revoked.status_code == 200, revoked.text

        listed = client.get(
            f"/api/v2/vpn/gateways/{gateway['id']}/peers", headers=operator_headers
        ).json()
        assert [row["id"] for row in listed["peers"]] == [kept["id"]]

        # Still visible when asked for explicitly, so the record survives the revocation.
        with_revoked = client.get(
            f"/api/v2/vpn/gateways/{gateway['id']}/peers?include_revoked=true",
            headers=operator_headers,
        ).json()
        assert len(with_revoked["peers"]) == 2

        # And its config is refused rather than quietly served.
        assert client.get(
            f"/api/v2/vpn/peers/{gone['id']}/config", headers=operator_headers
        ).status_code == 409


def test_revocation_is_idempotent():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("op"))
        gw_username = _unique("gwacct")
        register_verified(client, gw_username)
        gateway = _gateway(client, operator_headers, gw_username).json()
        peer = _enrol(client, operator_headers, gateway["id"]).json()

        first = client.post(
            f"/api/v2/vpn/peers/{peer['id']}/revoke", headers=operator_headers, json={}
        )
        second = client.post(
            f"/api/v2/vpn/peers/{peer['id']}/revoke", headers=operator_headers, json={}
        )
        assert first.status_code == second.status_code == 200
        assert first.json()["revoked_at"] == second.json()["revoked_at"]


def test_the_gateway_list_carries_sealed_keys_the_server_cannot_open():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("op"))
        gw_username = _unique("gwacct")
        register_verified(client, gw_username)
        gateway = _gateway(client, operator_headers, gw_username).json()
        _enrol(client, operator_headers, gateway["id"])

        listed = client.get(
            f"/api/v2/vpn/gateways/{gateway['id']}/peers", headers=operator_headers
        ).json()
        blob = listed["peers"][0]["sealed_psk"]

        # Present, because the gateway needs it; opaque, because only the gateway's
        # identity key opens it.
        assert blob
        assert len(base64.b64decode(blob)) > 1000, "a sealed hybrid ciphertext, not a raw key"


def test_a_stranger_cannot_see_or_change_another_operators_gateway():
    with TestClient(app) as client:
        owner_headers, _, _ = register_verified(client, _unique("op"))
        stranger_headers, _, _ = register_verified(client, _unique("other"))
        gw_username = _unique("gwacct")
        register_verified(client, gw_username)
        gateway = _gateway(client, owner_headers, gw_username).json()
        peer = _enrol(client, owner_headers, gateway["id"]).json()

        assert client.get(
            f"/api/v2/vpn/gateways/{gateway['id']}/peers", headers=stranger_headers
        ).status_code == 404
        assert _enrol(client, stranger_headers, gateway["id"]).status_code == 404
        assert client.post(
            f"/api/v2/vpn/peers/{peer['id']}/revoke", headers=stranger_headers, json={}
        ).status_code == 404
        assert client.get(
            f"/api/v2/vpn/peers/{peer['id']}/config", headers=stranger_headers
        ).status_code == 404


def test_a_malformed_wireguard_key_is_refused():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("op"))
        gw_username = _unique("gwacct")
        register_verified(client, gw_username)

        refused = _gateway(
            client,
            operator_headers,
            gw_username,
            wg_public_key=base64.b64encode(b"too short").decode(),
        )
        assert refused.status_code == 400


def test_an_unusable_network_is_refused():
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("op"))
        gw_username = _unique("gwacct")
        register_verified(client, gw_username)

        assert _gateway(
            client, operator_headers, gw_username, network_cidr="10.99.0.0/31"
        ).status_code == 400
        assert _gateway(
            client, operator_headers, gw_username, network_cidr="not-a-network"
        ).status_code == 400


def test_a_full_address_range_is_refused_rather_than_wrapping():
    """A /29 holds six usable hosts; the seventh enrolment must fail, not reuse .1."""
    with TestClient(app) as client:
        operator_headers, _, _ = register_verified(client, _unique("op"))
        gw_username = _unique("gwacct")
        register_verified(client, gw_username)
        gateway = _gateway(
            client, operator_headers, gw_username, network_cidr="10.50.0.0/29"
        ).json()

        issued = []
        for index in range(6):
            response = _enrol(client, operator_headers, gateway["id"], f"peer-{index}")
            if response.status_code != 200:
                break
            issued.append(response.json()["assigned_ip"])

        assert issued, "at least one peer should fit"
        assert len(set(issued)) == len(issued), "no address may be handed out twice"
        exhausted = _enrol(client, operator_headers, gateway["id"], "one-too-many")
        assert exhausted.status_code == 409
