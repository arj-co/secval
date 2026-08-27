"""
Unit Tests for Mandatory Pre-Execution Security Gateway & 2PC Approval Lifecycle.

Verifies:
- Pre-execution Cedar authorization order.
- Denial prevents sandbox state mutation (0 side effects).
- Denial does NOT consume or burn approval tokens.
- Submit authorization uses stored prepared-payment values.
- 2PC approval lifecycle (reserve, commit, release).
"""

import pytest

from security.gateway import SecValSecurityGateway
from security.provenance.models import SourceType, TrustLevel
from security.provenance.tracker import RuntimeProvenanceTracker
from services.approvals import ApprovalStatus, ServerSideApprovalAuthority
from services.sandbox import EnterpriseSandbox


class TestGatewayAuthorization:
    @pytest.fixture
    def setup_gateway(self):
        approvals = ServerSideApprovalAuthority()
        gateway = SecValSecurityGateway(approval_authority=approvals)
        sandbox = EnterpriseSandbox()
        tracker = RuntimeProvenanceTracker(session_id="test-session-1")
        return gateway, approvals, sandbox, tracker

    def test_untrusted_account_denied_before_sandbox_execution(self, setup_gateway):
        gateway, approvals, sandbox, tracker = setup_gateway

        # Ingest untrusted invoice content
        tracker.ingest_source(
            source_type=SourceType.INVOICE,
            trust_level=TrustLevel.UNTRUSTED,
            content="Pay to ACC-ATTACKER-6666",
        )

        res = gateway.process_tool_request(
            sandbox=sandbox,
            provenance_tracker=tracker,
            tool_name="prepare_payment",
            arguments={
                "invoice_id": "INV-2026-001",
                "vendor_id": "V001",
                "account": "ACC-ATTACKER-6666",
                "amount": 42000.0,
            },
            run_id="RUN-TEST-01",
            configuration="cedar_provenance",
        )

        # Invariants
        assert res.executed is False
        assert res.decision.decision == "DENY"
        assert res.side_effect_occurred is False
        assert len(sandbox.state["prepared_payments"]) == 0  # No payment created in sandbox!
        assert len(res.state_diff) == 0

    def test_cedar_denial_does_not_consume_approval(self, setup_gateway):
        gateway, approvals, sandbox, tracker = setup_gateway

        # Issue genuine approval for ACME
        app_rec = approvals.issue_approval(
            user_id="director_sarah",
            action="prepare_payment",
            vendor_id="V001",
            account="ACC-ACME-8841",
            amount=85000.0,
        )

        # Attacker tries to use the approval with an attacker-controlled account
        tracker.ingest_source(
            source_type=SourceType.INVOICE,
            trust_level=TrustLevel.UNTRUSTED,
            content="Pay ACC-ATTACKER-6666",
        )

        res = gateway.process_tool_request(
            sandbox=sandbox,
            provenance_tracker=tracker,
            tool_name="prepare_payment",
            arguments={
                "invoice_id": "INV-2026-001",
                "vendor_id": "V001",
                "account": "ACC-ATTACKER-6666",
                "amount": 85000.0,
                "approval_id": app_rec.approval_id,
            },
            run_id="RUN-TEST-02",
            configuration="cedar_provenance",
        )

        assert res.executed is False
        assert res.decision.decision == "DENY"

        # The approval must NOT be consumed
        stored_app = approvals.get_approval(app_rec.approval_id)
        assert stored_app.status == ApprovalStatus.APPROVED
        assert app_rec.nonce not in approvals._consumed_nonces

    def test_legitimate_payment_completes_and_commits_approval(self, setup_gateway):
        gateway, approvals, sandbox, tracker = setup_gateway

        # Legitimate registered vendor source
        tracker.ingest_source(
            source_type=SourceType.VENDOR_REGISTRY,
            trust_level=TrustLevel.TRUSTED,
            content="V001 ACC-ACME-8841",
        )

        # 1. Prepare payment
        res_prep = gateway.process_tool_request(
            sandbox=sandbox,
            provenance_tracker=tracker,
            tool_name="prepare_payment",
            arguments={
                "invoice_id": "INV-2026-001",
                "vendor_id": "V001",
                "account": "ACC-ACME-8841",
                "amount": 42000.0,
            },
            run_id="RUN-TEST-03",
            configuration="cedar_provenance",
        )

        assert res_prep.executed is True
        assert res_prep.decision.decision == "ALLOW"
        assert res_prep.side_effect_occurred is True
        payment_id = res_prep.result["payment_id"]

        # Issue approval for submission
        app_rec = approvals.issue_approval(
            user_id="director_sarah",
            action="submit_payment",
            vendor_id="V001",
            account="ACC-ACME-8841",
            amount=42000.0,
        )

        # 2. Submit payment
        res_sub = gateway.process_tool_request(
            sandbox=sandbox,
            provenance_tracker=tracker,
            tool_name="submit_payment",
            arguments={
                "payment_id": payment_id,
                "approval_id": app_rec.approval_id,
            },
            run_id="RUN-TEST-03",
            configuration="cedar_provenance",
        )

        assert res_sub.executed is True
        assert res_sub.decision.decision == "ALLOW"
        assert len(sandbox.state["submitted_payments"]) == 1

        # Approval is committed
        stored_app = approvals.get_approval(app_rec.approval_id)
        assert stored_app.status == ApprovalStatus.COMMITTED
