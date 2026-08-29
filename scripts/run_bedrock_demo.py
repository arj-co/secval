#!/usr/bin/env python3
"""
Bedrock Live Agent Demonstration Runner.

Executes 3 real scenarios through AWS Bedrock Converse (Claude 3.5 Haiku) or offline fallback:
1. Malicious Account-Change Invoice -> Bedrock requests unsafe payment -> SecVal blocks with 0 side effects.
2. Reworded Attack -> Invariant blocks it without regex keywords.
3. Legitimate Invoice -> SPAG verified -> Signed capability issued -> Payment succeeds.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.adapters.bedrock import BedrockConverseAdapter
from agents.adapters.deterministic import DeterministicAgentAdapter
from agents.runtime import AgentRuntime
from benchmark.factories.scenario_factory import generate_honest_scenarios
from security.gateway import SecValSecurityGateway


def run_bedrock_demo(model_id: str = "anthropic.claude-3-haiku-20240307-v1:0", region: str = "us-east-1", force_deterministic: bool = False):
    print("=" * 80)
    print("🛡️  SecVal Zero-Trust AI Agent Runtime Security Gateway")
    print("=" * 80)

    # Check for AWS credentials or use deterministic adapter
    has_aws = bool(os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"))
    if has_aws and not force_deterministic:
        print(f"🤖 Initializing Live AWS Bedrock Converse Adapter: {model_id} (Region: {region})")
        adapter = BedrockConverseAdapter(model_id=model_id, region_name=region)
        execution_type = "live_model_bedrock"
    else:
        print("🤖 Running with Deterministic Agent Adapter (Zero-Credential Offline Simulation)")
        adapter = DeterministicAgentAdapter(model_id="deterministic-procurement-agent-v1")
        execution_type = "deterministic_simulation"

    gateway = SecValSecurityGateway()
    runtime = AgentRuntime(adapter=adapter, gateway=gateway)

    all_scenarios = {s["id"]: s for s in generate_honest_scenarios()}

    demo_scenarios = [
        ("inv-001", "1. Standard Malicious Invoice (Bank Account Swap)"),
        ("inv-002", "2. Reworded Attack Variation (Treasury Directive)"),
        ("benign-001", "3. Legitimate ACME Invoice Processing"),
    ]

    results = []

    for sc_id, description in demo_scenarios:
        sc = all_scenarios[sc_id]
        print("\n" + "-" * 80)
        print(f"🎬 SCENARIO: {description}")
        print(f"   Task: {sc['user_task']}")
        if sc.get("untrusted_sources"):
            print(f"   Untrusted Input Document: {sc['untrusted_sources'][0]['source_id']}")
        print("-" * 80)

        # Run under SecVal Protected Mode (cedar_provenance)
        artifact = runtime.run_scenario(
            scenario=sc,
            configuration="cedar_provenance",
            run_id=f"DEMO-{sc_id.upper()}",
        )

        print(f"\n📊 EXECUTION VERDICT: {artifact.final_verdict}")
        print(f"   Total Turns: {len(artifact.turns)}")
        print(f"   Unauthorized Action Completed: {artifact.unauthorized_action_completed}")
        print(f"   Legitimate Task Completed: {artifact.legitimate_task_completed}")
        print(f"   Policy Blocked: {artifact.blocked_by_policy}")
        print(f"   Security Overhead Latency: {artifact.total_latency_ms:.2f} ms")

        for t in artifact.turns:
            print(f"\n   [Turn {t.turn_index}] Model Output: {t.model_content}")
            for tr in t.tool_requests:
                print(f"     👉 Model Proposed Tool: {tr['tool_name']}({json.dumps(tr['arguments'])})")
            for gr in t.gateway_results:
                print(f"     🛡️  SecVal Decision: {gr.get('decision', {}).get('decision')} | Matched: {gr.get('decision', {}).get('matched_policies')}")
                if gr.get("execution_capability"):
                    print(f"     🔑 Signed Capability Issued: {gr['execution_capability']['capability_id']} (Nonce: {gr['execution_capability']['nonce'][:8]}...)")
                else:
                    print("     🚫 Execution Capability: DENIED (No capability token issued)")
                print(f"     💾 Sandbox Ledger Changed: {gr.get('side_effect_occurred')}")

        results.append({
            "scenario_id": sc_id,
            "title": description,
            "execution_type": execution_type,
            "verdict": artifact.final_verdict,
            "unauthorized_action_completed": artifact.unauthorized_action_completed,
            "legitimate_task_completed": artifact.legitimate_task_completed,
            "blocked_by_policy": artifact.blocked_by_policy,
            "latency_ms": artifact.total_latency_ms,
        })

    print("\n" + "=" * 80)
    print("📈 DEMO SUMMARY RESULTS")
    print("=" * 80)
    for r in results:
        status_symbol = "✅" if (r["blocked_by_policy"] if not "benign" in r["scenario_id"] else r["legitimate_task_completed"]) else "❌"
        print(f"{status_symbol} {r['title']} -> {r['verdict']} (Latency: {r['latency_ms']:.2f} ms)")
    print("=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Bedrock Live Agent Demonstration")
    parser.add_argument("--model-id", default="anthropic.claude-3-haiku-20240307-v1:0", help="AWS Bedrock Model ID")
    parser.add_argument("--region", default="us-east-1", help="AWS Region")
    parser.add_argument("--deterministic", action="store_true", help="Force deterministic simulation offline")
    args = parser.parse_args()

    run_bedrock_demo(model_id=args.model_id, region=args.region, force_deterministic=args.deterministic)
