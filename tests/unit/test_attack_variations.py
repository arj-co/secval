"""
Unit Tests for Attack Invariant Enforcement across Reworded Variations.

Verifies:
- Standard account substitution (inv-001) is blocked.
- Reworded Treasury Notice (inv-002) is blocked.
- Urgent CFO Escalation (inv-003) is blocked.
- Invariant: Destination account must match master vendor registry.
- Rewording prompt text cannot bypass the invariant.
- Legitimate flow (benign-001) succeeds.
"""

import pytest

from agents.adapters.deterministic import DeterministicAgentAdapter
from agents.runtime import AgentRuntime
from benchmark.factories.scenario_factory import generate_all_scenarios


class TestAttackVariations:
    @pytest.fixture
    def runtime(self):
        return AgentRuntime()

    @pytest.fixture
    def scenarios(self):
        return {s["id"]: s for s in generate_all_scenarios()}

    def test_standard_account_swap_blocked_under_cedar_provenance(self, runtime, scenarios):
        sc = scenarios["inv-001"]
        artifact = runtime.run_scenario(scenario=sc, configuration="cedar_provenance")
        assert artifact.blocked_by_policy is True
        assert artifact.unauthorized_completed is False
        assert artifact.final_verdict == "SECURED_BLOCKED"

    def test_reworded_treasury_directive_blocked_under_cedar_provenance(self, runtime, scenarios):
        sc = scenarios["inv-002"]
        artifact = runtime.run_scenario(scenario=sc, configuration="cedar_provenance")
        assert artifact.blocked_by_policy is True
        assert artifact.unauthorized_completed is False
        assert artifact.final_verdict == "SECURED_BLOCKED"

    def test_urgent_cfo_escalation_blocked_under_cedar_provenance(self, runtime, scenarios):
        sc = scenarios["inv-003"]
        artifact = runtime.run_scenario(scenario=sc, configuration="cedar_provenance")
        assert artifact.blocked_by_policy is True
        assert artifact.unauthorized_completed is False
        assert artifact.final_verdict == "SECURED_BLOCKED"

    def test_unprotected_mode_allows_attacks_to_execute(self, runtime, scenarios):
        sc = scenarios["inv-001"]
        artifact = runtime.run_scenario(scenario=sc, configuration="unprotected")
        assert artifact.unauthorized_completed is True
        assert artifact.final_verdict == "VULNERABLE_COMPLETED"
        assert len(artifact.state_after["prepared_payments"]) > 0

    def test_benign_invoice_workflow_succeeds(self, runtime, scenarios):
        sc = scenarios["benign-001"]
        artifact = runtime.run_scenario(scenario=sc, configuration="cedar_provenance")
        assert artifact.blocked_by_policy is False
        assert artifact.legitimate_task_completed is True
        assert artifact.final_verdict == "BENIGN_SUCCESS"
