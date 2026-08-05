"""Invites, peer links, receipts and presence.

These exercise the paths a second operator actually travels: being invited, agreeing to a
link, and having their acknowledgements reach the sender. The cryptographic round trip is
covered in test_api_flow; what matters here is that consent and metadata behave.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

from fastapi.testclient import TestClient

from app.main import app
from test_api_flow import register_verified


def token_of(headers: dict) -> str:
    return headers["Authorization"].removeprefix("Bearer ")


def make_workspace(client: TestClient, headers: dict, name: str) -> dict:
    response = client.post("/api/v2/servers", headers=headers, json={"name": name})
    assert response.status_code == 200, response.text
    return response.json()


def test_invite_round_trip_opens_a_channel():
    with TestClient(app) as client:
        owner_headers, owner, _ = register_verified(client, "inv_owner")
        guest_headers, guest, _ = register_verified(client, "inv_guest")
        server = make_workspace(client, owner_headers, "Invite WS")

        created = client.post(
            "/api/v2/invites",
            headers=owner_headers,
            json={"server_id": server["id"], "max_uses": 1, "expires_in_hours": 1},
        )
        assert created.status_code == 200, created.text
        invite = created.json()
        code = invite["code"]
        assert invite["path"] == f"/join/{code}"

        # The code is returned once and never again: only its hash is stored.
        listed = client.get(f"/api/v2/servers/{server['id']}/invites", headers=owner_headers)
        assert listed.status_code == 200
        assert "code" not in listed.json()[0]
        assert listed.json()[0]["code_hint"] == code[:6]

        preview = client.get(f"/api/v2/invites/{code}/preview")
        assert preview.status_code == 200
        assert preview.json()["valid"] is True
        assert preview.json()["workspace_name"] == "Invite WS"
        assert preview.json()["invited_by"] == "inv_owner"

        accepted = client.post(f"/api/v2/invites/{code}/accept", headers=guest_headers)
        assert accepted.status_code == 200, accepted.text
        body = accepted.json()
        assert body["joined"] is True
        assert body["peer"] == "inv_owner"

        # Both ends can see the channel the invite opened.
        for headers in (owner_headers, guest_headers):
            channel = client.get(f"/api/v2/channels/{body['channel_id']}", headers=headers)
            assert channel.status_code == 200, channel.text
            assert channel.json()["hybrid_session_supported"] is True

        # A single-use invite is spent.
        second, _, _ = register_verified(client, "inv_late")
        again = client.post(f"/api/v2/invites/{code}/accept", headers=second)
        assert again.status_code == 409
        assert again.json()["detail"]["code"] == "invite_used_up"


def test_invite_revocation_and_unknown_code_are_indistinguishable():
    with TestClient(app) as client:
        owner_headers, _, _ = register_verified(client, "rev_owner")
        guest_headers, _, _ = register_verified(client, "rev_guest")
        server = make_workspace(client, owner_headers, "Revoke WS")

        invite = client.post(
            "/api/v2/invites",
            headers=owner_headers,
            json={"server_id": server["id"], "max_uses": 5},
        ).json()

        revoked = client.delete(f"/api/v2/invites/{invite['id']}", headers=owner_headers)
        assert revoked.status_code == 200

        blocked = client.post(f"/api/v2/invites/{invite['code']}/accept", headers=guest_headers)
        assert blocked.status_code == 409
        assert blocked.json()["detail"]["code"] == "invite_revoked"

        # A code that never existed reports 404, the same as any other unknown resource.
        assert client.get("/api/v2/invites/totally-made-up-code/preview").status_code == 404


def test_only_the_owner_can_mint_or_revoke_invites():
    with TestClient(app) as client:
        owner_headers, _, _ = register_verified(client, "auth_owner")
        outsider_headers, _, _ = register_verified(client, "auth_outsider")
        server = make_workspace(client, owner_headers, "Owned WS")

        attempt = client.post(
            "/api/v2/invites", headers=outsider_headers, json={"server_id": server["id"]}
        )
        assert attempt.status_code == 403
        assert (
            client.get(f"/api/v2/servers/{server['id']}/invites", headers=outsider_headers).status_code
            == 403
        )


def test_link_request_requires_consent_before_a_channel_exists():
    with TestClient(app) as client:
        a_headers, alice, _ = register_verified(client, "link_alice")
        b_headers, bob, _ = register_verified(client, "link_bob")

        requested = client.post("/api/v2/links", headers=a_headers, json={"username": "link_bob"})
        assert requested.status_code == 200, requested.text
        link = requested.json()
        assert link["status"] == "pending"
        # Nothing exists for either side until the target agrees.
        assert link["channel_id"] is None

        inbox = client.get("/api/v2/links", headers=b_headers).json()
        assert [row["id"] for row in inbox["incoming"]] == [link["id"]]
        assert client.get("/api/v2/links", headers=a_headers).json()["outgoing"][0]["id"] == link["id"]

        # A duplicate request while one is pending is refused.
        duplicate = client.post("/api/v2/links", headers=a_headers, json={"username": "link_bob"})
        assert duplicate.status_code == 409

        # The target answering a request they sent is steered to accepting instead.
        reciprocal = client.post("/api/v2/links", headers=b_headers, json={"username": "link_alice"})
        assert reciprocal.json()["status"] == "reciprocal_pending"

        accepted = client.post(f"/api/v2/links/{link['id']}/accept", headers=b_headers)
        assert accepted.status_code == 200, accepted.text
        channel_id = accepted.json()["channel_id"]

        for headers in (a_headers, b_headers):
            detail = client.get(f"/api/v2/channels/{channel_id}", headers=headers)
            assert detail.status_code == 200
            assert {m["username"] for m in detail.json()["members"]} == {"link_alice", "link_bob"}

        # Re-requesting an established link reports the existing channel.
        repeat = client.post("/api/v2/links", headers=a_headers, json={"username": "link_bob"})
        assert repeat.json()["status"] == "already_linked"
        assert repeat.json()["channel_id"] == channel_id


def test_link_decline_and_self_link_are_rejected():
    with TestClient(app) as client:
        a_headers, _, _ = register_verified(client, "dec_alice")
        b_headers, _, _ = register_verified(client, "dec_bob")

        assert (
            client.post("/api/v2/links", headers=a_headers, json={"username": "dec_alice"}).status_code
            == 400
        )

        link = client.post(
            "/api/v2/links", headers=a_headers, json={"username": "dec_bob"}
        ).json()
        declined = client.post(f"/api/v2/links/{link['id']}/decline", headers=b_headers)
        assert declined.status_code == 200
        assert declined.json()["status"] == "declined"

        # A declined request cannot then be accepted.
        assert client.post(f"/api/v2/links/{link['id']}/accept", headers=b_headers).status_code == 409
        # And the requester still has no channel with the target.
        assert client.get("/api/v2/links", headers=a_headers).json()["outgoing"] == []


def test_only_the_target_can_answer_a_link_request():
    with TestClient(app) as client:
        a_headers, _, _ = register_verified(client, "own_alice")
        b_headers, _, _ = register_verified(client, "own_bob")
        c_headers, _, _ = register_verified(client, "own_carol")

        link = client.post("/api/v2/links", headers=a_headers, json={"username": "own_bob"}).json()

        # A bystander cannot accept, and neither can the requester.
        assert client.post(f"/api/v2/links/{link['id']}/accept", headers=c_headers).status_code == 404
        assert client.post(f"/api/v2/links/{link['id']}/accept", headers=a_headers).status_code == 404
        assert client.post(f"/api/v2/links/{link['id']}/accept", headers=b_headers).status_code == 200
