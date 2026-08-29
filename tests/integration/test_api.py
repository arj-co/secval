"""
Integration Tests for SecVal Backend API Endpoints.

Verifies:
- GET /api/status
- GET /api/scenarios & GET /api/scenarios/{id}
- POST /api/runs/execute (single run under specific configuration)
- POST /api/runs/replay (side-by-side replay)
- POST /api/repair/propose (guided policy repair)
- GET /api/policies/current
"""

import pytest
from fastapi.testclient import TestClient

from backend.api.server import app


class TestBackendAPI:
    @pytest.fixture
    def client(self):
        return TestClient(app)

    def test_status_endpoint(self, client):
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "online"
        assert data["protection_mode"] == "Zero-Trust Runtime Gateway"
        assert "cedar_engine" in data

    def test_list_and_get_scenarios(self, client):
        resp = client.get("/api/scenarios")
        assert resp.status_code == 200
        scenarios = resp.json()
        assert len(scenarios) >= 10
        assert any(s["id"] == "inv-001" for s in scenarios)

        resp_single = client.get("/api/scenarios/inv-001")
        assert resp_single.status_code == 200
        assert resp_single.json()["id"] == "inv-001"

    def test_execute_run_endpoint(self, client):
        payload = {
            "scenario_id": "inv-001",
            "configuration": "cedar_provenance",
            "provider_type": "deterministic",
        }
        resp = client.post("/api/runs/execute", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_id"] == "inv-001"
        assert data["configuration"] == "cedar_provenance"
        assert data["blocked_by_policy"] is True
        assert data["final_verdict"] == "SECURED_BLOCKED"

    def test_replay_comparison_endpoint(self, client):
        payload = {
            "scenario_id": "inv-001",
            "provider_type": "deterministic",
        }
        resp = client.post("/api/runs/replay", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "unprotected" in data
        assert "protected" in data
        assert data["unprotected"]["unauthorized_completed"] is True
        assert data["protected"]["blocked_by_policy"] is True

    def test_guided_repair_propose_endpoint(self, client):
        payload = {
            "scenario_id": "inv-001",
        }
        resp = client.post("/api/repair/propose", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "violation_report" in data
        assert "candidate_patch" in data
        assert data["candidate_patch"]["status"] == "RECOMMENDED"
        assert data["candidate_patch"]["syntax_valid"] is True
        assert len(data["candidate_patch"]["ablation_table"]) > 0

    def test_get_current_policies(self, client):
        resp = client.get("/api/policies/current")
        assert resp.status_code == 200
        data = resp.json()
        assert "permit(" in data["policies"]
        assert "Procurement" in data["schema"]
