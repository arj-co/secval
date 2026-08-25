"""
Pre-Execution Gateway Policy Interceptor.

Implements ADR-001:
- Sits directly between the Agent and the Synthetic Sandbox tools.
- Attaches provenance and analyzes taint on sensitive arguments.
- Validates cryptographic server-side approvals.
- Invokes official Cedar authorization BEFORE any tool side effect occurs.
- Emits structured audit events distinguishing Attempts, Decisions, Denials, and Executions.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from security.cedar_engine import CedarDecision, CedarPolicyEngine
from security.provenance.models import SourceType, TrustLevel
from security.provenance.tracker import ProvenanceTracker
from services.approvals import ServerSideApprovalAuthority


@dataclass
class GatewayToolResult:
    tool_name: str
    arguments: Dict[str, Any]
    decision: CedarDecision
    executed: bool
    result: Any
    side_effect_occurred: bool
    side_effect_details: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "decision": self.decision.to_dict(),
            "executed": self.executed,
            "result": self.result,
            "side_effect_occurred": self.side_effect_occurred,
            "side_effect_details": self.side_effect_details,
            "error": self.error,
            "latency_ms": self.latency_ms,
        }


class PolicyGatewayInterceptor:
    """
    Zero-trust pre-execution gateway interceptor.
    Guarantees that unauthorized actions are blocked before execution.
    """

    def __init__(
        self,
        cedar_engine: Optional[CedarPolicyEngine] = None,
        approval_authority: Optional[ServerSideApprovalAuthority] = None,
        provenance_tracker: Optional[ProvenanceTracker] = None,
    ):
        self.cedar = cedar_engine or CedarPolicyEngine()
        self.approvals = approval_authority or ServerSideApprovalAuthority()
        self.provenance = provenance_tracker or ProvenanceTracker()
        self.audit_log: List[Dict[str, Any]] = []

    def dispatch(
        self,
        sandbox: Any,
        tool_name: str,
        arguments: Dict[str, Any],
        caller_id: str = "Procurement::Agent::\"orchestrator\"",
        configuration: str = "cedar_provenance",
        custom_policy_text: Optional[str] = None,
    ) -> GatewayToolResult:
        """
        Main interceptor entry point:
        1. Normalizes tool arguments & checks provenance.
        2. Validates server-side approval if present.
        3. Evaluates Cedar policy.
        4. If ALLOW -> executes sandbox tool.
        5. If DENY -> records denial, bypasses tool execution, returns policy error.
        """
        start_time = time.perf_counter()

        # Step 1: Argument normalization & provenance evaluation
        action_name = f"Procurement::Action::\"{tool_name}\""
        resource_name = "Procurement::System::\"sandbox\""
        
        # Analyze sensitive argument provenance
        account_val = arguments.get("account", "")
        vendor_id_val = arguments.get("vendor_id", "")
        to_email = arguments.get("to", "")
        approval_id = arguments.get("approval_id") or arguments.get("approval_token")

        # Check reference purchase order/vendor in sandbox if available
        trusted_refs = sandbox.get_trusted_references(vendor_id_val) if hasattr(sandbox, "get_trusted_references") else {}

        # Evaluate provenance taint for account
        account_prov = self.provenance.analyze_argument_provenance(
            arg_name="account",
            arg_value=account_val,
            explicit_source_ids=arguments.get("source_ids", []),
            trusted_reference_values=trusted_refs,
        )

        recipient_trust = "untrusted" if any(domain in to_email.lower() for domain in ["attacker", "external", "tempmail", "evil"]) else "trusted"

        # Step 2: Server-side Approval verification
        approval_valid = False
        has_valid_approval = False
        amount_val = float(arguments.get("amount", 0.0))

        if approval_id:
            has_valid_approval = True
            is_valid, app_reason, _ = self.approvals.validate_and_consume(
                approval_id=approval_id,
                action=tool_name,
                vendor_id=vendor_id_val,
                account=account_val,
                amount=amount_val,
                currency=arguments.get("currency", "INR"),
            )
            approval_valid = is_valid

        # Check preparation state if submitting payment
        is_prepared = False
        if tool_name == "submit_payment":
            payment_id = arguments.get("payment_id", "")
            is_prepared = sandbox.is_payment_prepared(payment_id) if hasattr(sandbox, "is_payment_prepared") else False

        # Step 3: Construct Cedar context
        is_external_email = any(d in to_email.lower() for d in ["attacker.com", "external.org", "gmail.com", "mailinator.com"])
        is_confidential = "confidential" in str(arguments.get("body", "")).lower() or "secret" in str(arguments.get("body", "")).lower()

        context: Dict[str, Any] = {
            "amount": int(round(amount_val)),
            "vendor_id": vendor_id_val,
            "account": account_val,
            "account_trust_level": account_prov.inferred_trust_level.value,
            "recipient_trust_level": recipient_trust,
            "is_tainted": account_prov.tainted,
            "has_valid_approval": has_valid_approval,
            "approval_valid": approval_valid,
            "is_prepared": is_prepared,
            "to": to_email,
            "has_confidential_content": is_confidential,
            "is_external_recipient": is_external_email,
            "email_id": arguments.get("email_id", ""),
            "invoice_id": arguments.get("invoice_id", ""),
            "payment_id": arguments.get("payment_id", ""),
            "approval_id": approval_id or "",
            "doc_path": arguments.get("doc_path", ""),
            "is_protected_doc": True if arguments.get("doc_path") else False,
        }

        # Step 4: Evaluate Cedar Policy
        decision = self.cedar.evaluate(
            principal=caller_id,
            action=action_name,
            resource=resource_name,
            context=context,
            custom_policy_text=custom_policy_text,
            configuration=configuration,
        )

        audit_event = {
            "timestamp": time.time(),
            "caller_id": caller_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "configuration": configuration,
            "provenance": {
                "account_trust_level": account_prov.inferred_trust_level.value,
                "is_tainted": account_prov.tainted,
                "taint_reason": account_prov.taint_reason,
            },
            "decision": decision.to_dict(),
        }

        # Step 5: Execution Gate (ALLOW vs DENY)
        if not decision.is_allowed():
            audit_event["executed"] = False
            audit_event["side_effect_occurred"] = False
            audit_event["outcome"] = "BLOCKED_BY_POLICY"
            self.audit_log.append(audit_event)
            self.provenance.record_tool_event(audit_event)

            elapsed = (time.perf_counter() - start_time) * 1000.0
            return GatewayToolResult(
                tool_name=tool_name,
                arguments=arguments,
                decision=decision,
                executed=False,
                result={"error": "ACCESS_DENIED", "reason": decision.reason, "matched_policies": decision.matched_policies},
                side_effect_occurred=False,
                error=decision.reason,
                latency_ms=elapsed,
            )

        # Step 6: Tool Execution (Only after ALLOW)
        try:
            tool_fn = getattr(sandbox, tool_name, None)
            if not tool_fn:
                raise ValueError(f"Unknown sandbox tool '{tool_name}'")

            tool_output, side_effect_details = tool_fn(**arguments)
            side_effect_occurred = side_effect_details.get("state_changed", False)

            audit_event["executed"] = True
            audit_event["side_effect_occurred"] = side_effect_occurred
            audit_event["side_effect_details"] = side_effect_details
            audit_event["outcome"] = "EXECUTED_SUCCESSFULLY"
            self.audit_log.append(audit_event)
            self.provenance.record_tool_event(audit_event)

            elapsed = (time.perf_counter() - start_time) * 1000.0
            return GatewayToolResult(
                tool_name=tool_name,
                arguments=arguments,
                decision=decision,
                executed=True,
                result=tool_output,
                side_effect_occurred=side_effect_occurred,
                side_effect_details=side_effect_details,
                latency_ms=elapsed,
            )
        except Exception as exc:
            audit_event["executed"] = False
            audit_event["side_effect_occurred"] = False
            audit_event["error"] = str(exc)
            audit_event["outcome"] = "EXECUTION_ERROR"
            self.audit_log.append(audit_event)

            elapsed = (time.perf_counter() - start_time) * 1000.0
            return GatewayToolResult(
                tool_name=tool_name,
                arguments=arguments,
                decision=decision,
                executed=False,
                result={"error": str(exc)},
                side_effect_occurred=False,
                error=str(exc),
                latency_ms=elapsed,
            )

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        return list(self.audit_log)

    def reset(self) -> None:
        self.audit_log.clear()
        self.approvals.reset()
        self.provenance.reset()
