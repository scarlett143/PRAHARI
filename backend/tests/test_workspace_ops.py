"""Renaming, deleting and changing who is in a workspace.

The one with security weight is removal. Dropping a membership row stops the relay handing
someone new envelopes, but they still hold the current epoch's key and could read anything
sent under it. Advancing the epoch is what actually ends access, so that is what these
tests pin.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

from fastapi.testclient import TestClient

from app.main import app

from test_api_flow import register_verified
from test_fleet import _unique


def _workspace(client: TestClient, headers, name="Ops"):
    response = client.post("/api/v2/servers", headers=headers, json={"name": name})
    assert response.status_code == 200, response.text
    return response.json()


def _add(client: TestClient, headers, server_id, username):
    return client.post(
        f"/api/v2/servers/{server_id}/members", headers=headers, json={"username": username}
    )


def test_an_owner_can_rename_a_workspace():
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, _unique("owner"))
        server = _workspace(client, headers)

        renamed = client.patch(
            f"/api/v2/servers/{server['id']}", headers=headers, json={"name": "Recon"}
        )
        assert renamed.status_code == 200, renamed.text
        assert renamed.json()["name"] == "Recon"

        listed = client.get("/api/v2/servers", headers=headers).json()
        assert [row["name"] for row in listed if row["id"] == server["id"]] == ["Recon"]


def test_a_member_cannot_rename_or_delete_someone_elses_workspace():
    with TestClient(app) as client:
        owner_headers, _, _ = register_verified(client, _unique("owner"))
        member_headers, member, _ = register_verified(client, _unique("member"))
        server = _workspace(client, owner_headers)
        _add(client, owner_headers, server["id"], member["username"])

        assert client.patch(
            f"/api/v2/servers/{server['id']}", headers=member_headers, json={"name": "Mine now"}
        ).status_code == 403
        assert client.delete(
            f"/api/v2/servers/{server['id']}", headers=member_headers
        ).status_code == 403


def test_removing_a_member_rotates_every_channel_they_were_in():
    """A membership row is bookkeeping; the epoch is the access."""
    with TestClient(app) as client:
        owner_headers, _, _ = register_verified(client, _unique("owner"))
        member_headers, member, _ = register_verified(client, _unique("member"))
        server = _workspace(client, owner_headers)
        _add(client, owner_headers, server["id"], member["username"])

        channel_id = server["channels"][0]["id"]
        before = client.get(f"/api/v2/channels/{channel_id}", headers=owner_headers).json()

        removed = client.delete(
            f"/api/v2/servers/{server['id']}/members/{member['id']}", headers=owner_headers
        )
        assert removed.status_code == 200, removed.text
        assert channel_id in removed.json()["rotated"]

        after = client.get(f"/api/v2/channels/{channel_id}", headers=owner_headers).json()
        assert after["key_epoch"] > before["key_epoch"], (
            "without a rotation the removed member still holds a usable key"
        )

        # And the relay stops serving them the channel at all.
        assert client.get(
            f"/api/v2/channels/{channel_id}", headers=member_headers
        ).status_code == 404


def test_the_owner_can_neither_be_removed_nor_leave():
    """Either would strand a workspace nobody can administer."""
    with TestClient(app) as client:
        owner_headers, owner, _ = register_verified(client, _unique("owner"))
        server = _workspace(client, owner_headers)

        assert client.delete(
            f"/api/v2/servers/{server['id']}/members/{owner['id']}", headers=owner_headers
        ).status_code == 409
        assert client.post(
            f"/api/v2/servers/{server['id']}/leave", headers=owner_headers
        ).status_code == 409


def test_a_member_can_leave_and_the_workspace_survives():
    with TestClient(app) as client:
        owner_headers, _, _ = register_verified(client, _unique("owner"))
        member_headers, member, _ = register_verified(client, _unique("member"))
        server = _workspace(client, owner_headers)
        _add(client, owner_headers, server["id"], member["username"])

        left = client.post(f"/api/v2/servers/{server['id']}/leave", headers=member_headers)
        assert left.status_code == 200, left.text
        assert left.json()["rotated"], "leaving must rotate too, for the same reason removal does"

        # Gone for them, intact for the owner.
        assert server["id"] not in [row["id"] for row in client.get("/api/v2/servers", headers=member_headers).json()]
        assert server["id"] in [row["id"] for row in client.get("/api/v2/servers", headers=owner_headers).json()]


def test_deleting_a_workspace_takes_its_channels_with_it():
    with TestClient(app) as client:
        owner_headers, _, _ = register_verified(client, _unique("owner"))
        server = _workspace(client, owner_headers)
        channel_id = server["channels"][0]["id"]

        deleted = client.delete(f"/api/v2/servers/{server['id']}", headers=owner_headers)
        assert deleted.status_code == 200, deleted.text

        assert server["id"] not in [
            row["id"] for row in client.get("/api/v2/servers", headers=owner_headers).json()
        ]
        # A channel outliving its workspace would be unreachable rather than merely orphaned.
        assert client.get(
            f"/api/v2/channels/{channel_id}", headers=owner_headers
        ).status_code == 404


def test_a_stranger_cannot_leave_a_workspace_they_were_never_in():
    with TestClient(app) as client:
        owner_headers, _, _ = register_verified(client, _unique("owner"))
        stranger_headers, _, _ = register_verified(client, _unique("stranger"))
        server = _workspace(client, owner_headers)

        assert client.post(
            f"/api/v2/servers/{server['id']}/leave", headers=stranger_headers
        ).status_code == 404
