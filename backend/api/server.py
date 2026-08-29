"""
SecVal FastAPI Backend Server.

Provides REST endpoints for:
- Agent Security Gateway runtime execution
- Side-by-side comparative replay
- Timeline trace and state diff inspection
- Guided Policy Repair with real ablation testing
- Benchmark execution and metric aggregation
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from agents.adapters.bedrock import BedrockConverseAdapter
from agents.adapters.deterministic import DeterministicAgentAdapter
from agents.runtime import AgentRuntime
from benchmark.factories.scenario_factory import generate_all_scenarios
from benchmark.runner import BenchmarkRunner
from security.cedar_engine import CedarPolicyEngine
from security.gateway import SecValSecurityGateway
from security.repair.agent import GuidedPolicyRepairEngine

app = FastAPI(
    title="SecVal Agent Security Control Center API",
    description="Zero-Trust Runtime Security Gateway for Tool-Using AI Agents.",
    version="2.0.0",
)

# CORS configuration restricted to frontend origins
allowed_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://dashboard:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

repo_root = Path(__file__).resolve().parent.parent.parent
results_dir = repo_root / "benchmark" / "results"
results_dir.mkdir(parents=True, exist_ok=True)

cedar_engine = CedarPolicyEngine()
gateway = SecValSecurityGateway(cedar_engine=cedar_engine)
runtime = AgentRuntime(gateway=gateway)
runner = BenchmarkRunner(results_dir=results_dir, gateway=gateway)
repair_engine = GuidedPolicyRepairEngine(cedar_engine=cedar_engine)

scenarios_map = {s["id"]: s for s in generate_all_scenarios()}


# --- Request & Response Models ---

class RunExecutionRequest(BaseModel):
    scenario_id: str
    configuration: str = Field(default="cedar_provenance", description="unprotected | prompt_only | cedar_only | cedar_provenance")
    provider_type: str = Field(default="deterministic", description="deterministic | bedrock")
    model_id: Optional[str] = None
    custom_policy: Optional[str] = None


class ReplayRequest(BaseModel):
    scenario_id: str
    provider_type: str = Field(default="deterministic", description="deterministic | bedrock")
    model_id: Optional[str] = None


class RepairRequest(BaseModel):
    scenario_id: str
    run_record: Optional[Dict[str, Any]] = None


# --- API Endpoints ---

@app.get("/api/status")
def get_system_status() -> Dict[str, Any]:
    cedar_cli_available = cedar_engine._find_cedar_cli() is not None
    bedrock_configured = bool(os.environ.get("AWS_PROFILE") or os.environ.get("AWS_ACCESS_KEY_ID"))
    return {
        "status": "online",
        "protection_mode": "Zero-Trust Runtime Gateway",
        "cedar_engine": "Official Cedar CLI v4.3.0" if cedar_cli_available else "Fallback (Test Mode Only)",
        "cedar_cli_available": cedar_cli_available,
        "bedrock_available": bedrock_configured,
        "scenarios_loaded": len(scenarios_map),
        "supported_configurations": ["unprotected", "prompt_only", "cedar_only", "cedar_provenance"],
        "signing_secret_loaded": bool(os.environ.get("SECVAL_SIGNING_SECRET") or os.environ.get("ENVIRONMENT") != "production"),
    }


@app.get("/api/health")
def get_health() -> Dict[str, Any]:
    return get_system_status()


@app.get("/api/scenarios")
def list_scenarios(category: Optional[str] = None) -> List[Dict[str, Any]]:
    scs = list(scenarios_map.values())
    if category:
        scs = [s for s in scs if s.get("category") == category]
    return scs


@app.get("/api/scenarios/{scenario_id}")
def get_scenario(scenario_id: str) -> Dict[str, Any]:
    sc = scenarios_map.get(scenario_id)
    if not sc:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    return sc


@app.post("/api/runs/execute")
def execute_run(req: RunExecutionRequest) -> Dict[str, Any]:
    sc = scenarios_map.get(req.scenario_id)
    if not sc:
        raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found.")

    adapter = None
    if req.provider_type == "bedrock":
        try:
            adapter = BedrockConverseAdapter(model_id=req.model_id)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to initialize AWS Bedrock adapter: {exc}")
    else:
        adapter = DeterministicAgentAdapter(model_id=req.model_id or "deterministic-procurement-agent-v1")

    artifact = runtime.run_scenario(
        scenario=sc,
        configuration=req.configuration,
        adapter=adapter,
        custom_policy_text=req.custom_policy,
    )
    return artifact.to_dict()


@app.post("/api/runs/replay")
def replay_comparison(req: ReplayRequest) -> Dict[str, Any]:
    """Execute both unprotected baseline and cedar_provenance protected modes side-by-side."""
    sc = scenarios_map.get(req.scenario_id)
    if not sc:
        raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found.")

    adapter = None
    if req.provider_type == "bedrock":
        try:
            adapter = BedrockConverseAdapter(model_id=req.model_id)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"AWS Bedrock error: {exc}")
    else:
        adapter = DeterministicAgentAdapter(model_id=req.model_id or "deterministic-procurement-agent-v1")

    unprotected_artifact = runtime.run_scenario(
        scenario=sc,
        configuration="unprotected",
        adapter=adapter,
    )
    protected_artifact = runtime.run_scenario(
        scenario=sc,
        configuration="cedar_provenance",
        adapter=adapter,
    )

    return {
        "scenario": sc,
        "unprotected": unprotected_artifact.to_dict(),
        "protected": protected_artifact.to_dict(),
    }


@app.get("/api/experiments/latest")
def get_latest_experiment() -> Dict[str, Any]:
    latest_file = results_dir / "latest_manifest.json"
    if not latest_file.exists():
        return runner.run_experiment(repetitions=1)
    return json.loads(latest_file.read_text(encoding="utf-8"))


@app.post("/api/benchmark/run")
def trigger_benchmark(repetitions: int = 1) -> Dict[str, Any]:
    manifest = runner.run_experiment(repetitions=repetitions)
    return manifest


@app.post("/api/repair/propose")
def propose_repair(req: RepairRequest) -> Dict[str, Any]:
    sc = scenarios_map.get(req.scenario_id)
    if not sc:
        raise HTTPException(status_code=404, detail=f"Scenario '{req.scenario_id}' not found.")

    run_record = req.run_record or {
        "scenario_id": req.scenario_id,
        "unauthorized_action_completed": True,
    }

    violation = repair_engine.create_violation_report(sc, run_record)
    rule_name, candidate_rule, explanation = repair_engine.synthesize_candidate_rule(violation)

    evaluation = repair_engine.validate_and_test_candidate(
        candidate_cedar_rule=candidate_rule,
        rule_name=rule_name,
        explanation=explanation,
        violation=violation,
        all_scenarios=list(scenarios_map.values()),
    )

    return {
        "violation_report": violation.to_dict(),
        "candidate_patch": evaluation.to_dict(),
    }


@app.get("/api/policies/current")
def get_current_policies() -> Dict[str, Any]:
    policies_text = cedar_engine._load_default_policies()
    schema_text = ""
    if cedar_engine.schema_path.exists():
        schema_text = cedar_engine.schema_path.read_text(encoding="utf-8")
    return {
        "policies": policies_text,
        "schema": schema_text,
    }
