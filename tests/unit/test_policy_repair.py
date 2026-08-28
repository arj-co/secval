"""
Unit Tests for Guided Policy Repair & Empirical Ablation.

Verifies:
- Violation report generation on real attack bypass.
- Candidate Cedar policy rule synthesis.
- Official Cedar syntax validation (`cedar validate`).
- Real ablation testing comparing outcomes without vs with candidate policy.
- Status is 'RECOMMENDED' with 0 benign regressions.
"""

import pytest

from benchmark.factories.scenario_factory import generate_all_scenarios
from security.repair.agent import GuidedPolicyRepairEngine


class TestGuidedPolicyRepair:
    @pytest.fixture
    def repair_engine(self):
        return GuidedPolicyRepairEngine()

    @pytest.fixture
    def scenarios(self):
        return generate_all_scenarios()

    def test_guided_repair_for_invoice_account_swap(self, repair_engine, scenarios):
        target_scenario = next(s for s in scenarios if s["id"] == "inv-001")
        run_record = {"scenario_id": "inv-001", "unauthorized_action_completed": True}

        # 1. Forensic Report
        violation = repair_engine.create_violation_report(target_scenario, run_record)
        assert violation.threat_category == "malicious_invoice"
        assert "master vendor registry" in violation.violated_invariant

        # 2. Rule Synthesis
        rule_name, candidate_rule, explanation = repair_engine.synthesize_candidate_rule(violation)
        assert "forbid" in candidate_rule
        assert "account_trust_level" in candidate_rule

        # 3. Validation & Ablation Testing
        evaluation = repair_engine.validate_and_test_candidate(
            candidate_cedar_rule=candidate_rule,
            rule_name=rule_name,
            explanation=explanation,
            violation=violation,
            all_scenarios=scenarios,
        )

        assert evaluation.syntax_valid is True
        assert evaluation.target_attack_blocked is True
        assert evaluation.benign_regressions_count == 0
        assert evaluation.false_positive_rate == 0.0
        assert evaluation.status == "RECOMMENDED"
        assert len(evaluation.ablation_table) > 0
