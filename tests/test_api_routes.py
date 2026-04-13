"""Tests for API routes using FastAPI TestClient."""
import pytest


class TestStatusEndpoint:
    def test_get_status_200(self, client):
        resp = client.get("/api/v1/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        payload = data["data"]
        assert payload["system"] == "SentinelHome"
        assert "version" in payload
        assert "uptime_seconds" in payload
        assert "db_ok" in payload
        assert "queue_depth" in payload


class TestNotesEndpoints:
    def test_create_and_list_note(self, client):
        # Create
        resp = client.post("/api/v1/notes", json={
            "entity_type": "general",
            "text": "Test note from unit tests",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        note = data["data"]
        assert note["text"] == "Test note from unit tests"
        assert note["entity_type"] == "general"
        note_id = note["id"]

        # List
        resp = client.get("/api/v1/notes")
        assert resp.status_code == 200
        notes = resp.json()["data"]
        assert any(n["id"] == note_id for n in notes)

    def test_delete_note(self, client):
        # Create first
        resp = client.post("/api/v1/notes", json={
            "entity_type": "general",
            "text": "To be deleted",
        })
        note_id = resp.json()["data"]["id"]

        # Delete
        resp = client.delete(f"/api/v1/notes/{note_id}")
        assert resp.status_code == 200
        assert resp.json()["data"]["deleted"] == note_id

        # Verify gone
        resp = client.get(f"/api/v1/notes/{note_id}")
        assert resp.status_code == 404

    def test_delete_nonexistent_note(self, client):
        resp = client.delete("/api/v1/notes/999999")
        assert resp.status_code == 404

    def test_create_note_invalid_entity_type(self, client):
        resp = client.post("/api/v1/notes", json={
            "entity_type": "invalid_type",
            "text": "Should fail",
        })
        assert resp.status_code == 400


class TestContextEndpoint:
    def test_device_context_nonexistent(self, client):
        resp = client.get("/api/v1/context/device/aa:bb:cc:dd:ee:ff")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        context = data["data"]["context"]
        assert "unknown" in context.lower() or "aa:bb:cc:dd:ee:ff" in context

    def test_context_invalid_entity_type(self, client):
        resp = client.get("/api/v1/context/invalid_type/123")
        assert resp.status_code == 400


class TestEventFlagEndpoint:
    def test_flag_nonexistent_event(self, client):
        resp = client.post("/api/v1/events/999999/flag")
        assert resp.status_code == 404
