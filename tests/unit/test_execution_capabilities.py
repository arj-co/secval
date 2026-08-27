"""
Unit Tests for Cryptographically Signed Execution Capabilities.

Tests:
1. Valid capability issuance, cryptographic HMAC verification, and consumption.
2. Replay attack prevention (single-use nonce).
3. Argument tampering detection (post-authorization argument modification).
4. Cross-session capability replay prevention.
5. Expired capability rejection.
6. Direct sandbox invocation without capability rejection.
"""

import time
import pytest
from services.capabilities import CapabilityAuthority, CapabilityStatus
from services.sandbox import EnterpriseSandbox


class TestExecutionCapabilities:

    def test_valid_capability_lifecycle(self):
        auth = CapabilityAuthority()
        arguments = {"invoice_id": "INV-001", "vendor_id": "V001", "account": "ACC-ACME-8841", "amount": 42000.0, "currency": "INR"}

        cap = auth.issue_capability(
            tool_name="prepare_payment",
            arguments=arguments,
            transaction_id="TX-INV-001",
            spag_graph_hash="graphhash123",
            policy_hash="policyhash123",
            session_id="session_alpha",
            ttl_seconds=60,
        )

        assert cap.status == CapabilityStatus.ISSUED
        assert cap.capability_id.startswith("CAP-")
        assert len(cap.signature) == 64

        # Consume capability
        is_valid, msg, rec = auth.verify_and_consume(
            capability_id=cap.capability_id,
            tool_name="prepare_payment",
            arguments=arguments,
            session_id="session_alpha",
        )

        assert is_valid is True
        assert rec.status == CapabilityStatus.CONSUMED

    def test_replay_attack_rejected(self):
        auth = CapabilityAuthority()
        arguments = {"invoice_id": "INV-001", "vendor_id": "V001", "account": "ACC-ACME-8841", "amount": 42000.0, "currency": "INR"}

        cap = auth.issue_capability(
            tool_name="prepare_payment",
            arguments=arguments,
            transaction_id="TX-INV-001",
            spag_graph_hash="graphhash123",
            policy_hash="policyhash123",
            session_id="session_alpha",
        )

        # First consumption succeeds
        valid1, _, _ = auth.verify_and_consume(cap.capability_id, "prepare_payment", arguments, "session_alpha")
        assert valid1 is True

        # Second consumption (Replay Attack) must be rejected
        valid2, msg2, _ = auth.verify_and_consume(cap.capability_id, "prepare_payment", arguments, "session_alpha")
        assert valid2 is False
        assert "already been consumed" in msg2

    def test_argument_swapping_tampering_rejected(self):
        auth = CapabilityAuthority()
        authorized_args = {"invoice_id": "INV-001", "vendor_id": "V001", "account": "ACC-ACME-8841", "amount": 42000.0, "currency": "INR"}

        cap = auth.issue_capability(
            tool_name="prepare_payment",
            arguments=authorized_args,
            transaction_id="TX-INV-001",
            spag_graph_hash="graphhash123",
            policy_hash="policyhash123",
            session_id="session_alpha",
        )

        # Attacker modifies account to attacker account after authorization
        tampered_args = {"invoice_id": "INV-001", "vendor_id": "V001", "account": "ACC-ATTACKER-6666", "amount": 42000.0, "currency": "INR"}

        is_valid, msg, _ = auth.verify_and_consume(
            capability_id=cap.capability_id,
            tool_name="prepare_payment",
            arguments=tampered_args,
            session_id="session_alpha",
        )

        assert is_valid is False
        assert "arguments mismatch" in msg

    def test_cross_session_capability_rejected(self):
        auth = CapabilityAuthority()
        args = {"invoice_id": "INV-001", "vendor_id": "V001", "account": "ACC-ACME-8841", "amount": 42000.0, "currency": "INR"}

        cap = auth.issue_capability(
            tool_name="prepare_payment",
            arguments=args,
            transaction_id="TX-INV-001",
            spag_graph_hash="graphhash123",
            policy_hash="policyhash123",
            session_id="session_alpha",
        )

        # Presented in a different session
        is_valid, msg, _ = auth.verify_and_consume(
            capability_id=cap.capability_id,
            tool_name="prepare_payment",
            arguments=args,
            session_id="session_beta",
        )

        assert is_valid is False
        assert "session mismatch" in msg

    def test_expired_capability_rejected(self):
        auth = CapabilityAuthority()
        args = {"invoice_id": "INV-001", "vendor_id": "V001", "account": "ACC-ACME-8841", "amount": 42000.0, "currency": "INR"}

        cap = auth.issue_capability(
            tool_name="prepare_payment",
            arguments=args,
            transaction_id="TX-INV-001",
            spag_graph_hash="graphhash123",
            policy_hash="policyhash123",
            session_id="session_alpha",
            ttl_seconds=10,
        )

        # Present 15 seconds later
        is_valid, msg, _ = auth.verify_and_consume(
            capability_id=cap.capability_id,
            tool_name="prepare_payment",
            arguments=args,
            session_id="session_alpha",
            current_time=time.time() + 20,
        )

        assert is_valid is False
        assert "expired" in msg

    def test_direct_sandbox_invocation_without_capability_rejected(self):
        auth = CapabilityAuthority()
        sandbox = EnterpriseSandbox(capability_authority=auth, enforce_capabilities=True, session_id="sess_123")

        # Direct invocation lacking capability token
        output, side_effect = sandbox.prepare_payment(
            invoice_id="INV-001",
            vendor_id="V001",
            account="ACC-ACME-8841",
            amount=42000.0,
            currency="INR",
        )

        assert "EXECUTION_CAPABILITY_DENIED" in output.get("error", "")
        assert side_effect.get("state_changed") is False
        assert len(sandbox.state["prepared_payments"]) == 0
