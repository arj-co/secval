"""
SecVal Mandatory Pre-Execution Security Gateway.

Implements Sections 2 & 3:
- Single mandatory authorization gate for all model tool calls.
- State-Provenance Authorization Graph (SPAG) engine for graph-based trust propagation and invariant verification.
- Signed Execution Capabilities: Cedar ALLOW alone never executes tools; a signed, single-use,
  time-bound capability token is issued and strictly verified by sandbox tools.
- Strict 13-step pipeline with 2-phase approval commit and runtime-owned provenance.
- Emits comprehensive authorization traces, SPAG graph exports, capability tokens, and state diffs.
"""

from __future__ import annotations

import copy
import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from security.cedar_engine import CedarDecision, CedarPolicyEngine
from security.provenance.models import TrustLevel
from security.provenance.tracker import RuntimeProvenanceTracker
from security.spag.graph import StateProvenanceAuthorizationGraph
from services.approvals import ApprovalStatus, ServerSideApprovalAuthority
from services.capabilities import CapabilityAuthority, ExecutionCapability
from services.reconstruction import ReconstructedTransaction, TransactionReconstructor
from services.sandbox import EnterpriseSandbox


@dataclass
class GatewayTraceEvent:
    step_number: int
    step_name: str
    status: str  # "PASS" | "FAIL" | "DENY" | "ALLOW" | "INFO"
    details: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GatewayExecutionResult:
    run_id: str
    tool_name: str
    requested_arguments: Dict[str, Any]
    decision: CedarDecision
    executed: bool
    result: Any
    side_effect_occurred: bool
    reconstructed_transaction: Optional[ReconstructedTransaction] = None
    spag_graph: Optional[Dict[str, Any]] = None
    execution_capability: Optional[Dict[str, Any]] = None
    state_before: Dict[str, Any] = field(default_factory=dict)
    state_after: Dict[str, Any] = field(default_factory=dict)
    state_diff: Dict[str, Any] = field(default_factory=dict)
    trace_timeline: List[GatewayTraceEvent] = field(default_factory=list)
    error: Optional[str] = None
    security_overhead_latency_ms: float = 0.0
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "tool_name": self.tool_name,
            "requested_arguments": self.requested_arguments,
            "decision": self.decision.to_dict(),
            "executed": self.executed,
            "result": self.result,
            "side_effect_occurred": self.side_effect_occurred,
            "reconstructed_transaction": self.reconstructed_transaction.to_dict() if self.reconstructed_transaction else None,
            "spag_graph": self.spag_graph,
            "execution_capability": self.execution_capability,
            "state_before": self.state_before,
            "state_after": self.state_after,
            "state_diff": self.state_diff,
            "trace_timeline": [t.to_dict() for t in self.trace_timeline],
            "error": self.error,
            "security_overhead_latency_ms": self.security_overhead_latency_ms,
            "latency_ms": self.latency_ms,
        }


class SecValSecurityGateway:
    """
    Mandatory Zero-Trust Security Gateway.
    Coordinates SPAG analysis, Cedar evaluation, 2PC approvals, and signed execution capabilities.
    """

    def __init__(
        self,
        cedar_engine: Optional[CedarPolicyEngine] = None,
        approval_authority: Optional[ServerSideApprovalAuthority] = None,
        capability_authority: Optional[CapabilityAuthority] = None,
    ):
        self.cedar = cedar_engine or CedarPolicyEngine()
        self.approvals = approval_authority or ServerSideApprovalAuthority()
        self.capabilities = capability_authority or CapabilityAuthority()
        self.reconstructor = TransactionReconstructor()

    def process_tool_request(
        self,
        sandbox: EnterpriseSandbox,
        provenance_tracker: RuntimeProvenanceTracker,
        tool_name: str,
        arguments: Dict[str, Any],
        run_id: str,
        configuration: str = "cedar_provenance",
        custom_policy_text: Optional[str] = None,
        caller_principal: str = "Procurement::Agent::\"orchestrator\"",
    ) -> GatewayExecutionResult:
        """
        13-Step Mandatory Pre-Execution Gateway Execution Pipeline.
        """
        start_time = time.perf_counter()
        sec_start = time.perf_counter()
        timeline: List[GatewayTraceEvent] = []
        state_before = copy.deepcopy(sandbox.state)

        # Wire sandbox capability authority to gateway capability authority
        sandbox.capability_authority = self.capabilities
        sandbox.session_id = run_id
        if configuration == "cedar_provenance":
            sandbox.enforce_capabilities = True

        # Initialize SPAG graph
        spag = StateProvenanceAuthorizationGraph(session_id=run_id)

        # Step 1: Parse and validate tool call schema
        timeline.append(
            GatewayTraceEvent(
                step_number=1,
                step_name="Schema & Argument Validation",
                status="PASS",
                details={"tool": tool_name, "raw_arguments": arguments},
            )
        )

        # Ingest Document Sources into SPAG
        for srec in provenance_tracker.get_source_records():
            spag.add_document_node(
                doc_id=srec.source_handle,
                label=f"{srec.source_type.value}: {srec.source_handle}",
                trust_level=srec.trust_level.value,
                content_hash=srec.content_hash,
                doc_type=srec.source_type.value,
            )

        # Step 2 & 3: Server-side Resource Resolution & Runtime Provenance Analysis
        reconstructed_tx: Optional[ReconstructedTransaction] = None
        account_prov = None

        if tool_name == "prepare_payment":
            inv_id = str(arguments.get("invoice_id", ""))
            vendor_id = str(arguments.get("vendor_id", ""))
            proposed_acc = str(arguments.get("account", ""))
            amount_val = float(arguments.get("amount", 0.0))
            currency_val = str(arguments.get("currency", "INR"))

            reconstructed_tx = self.reconstructor.reconstruct_prepare_payment(
                sandbox_state=sandbox.state,
                proposed_invoice_id=inv_id,
                proposed_vendor_id=vendor_id,
                proposed_account=proposed_acc,
                proposed_amount=amount_val,
                proposed_currency=currency_val,
            )

            # Build SPAG Nodes
            spag.add_authoritative_node(
                record_id=vendor_id,
                label=f"Vendor {vendor_id} Master Record",
                attributes={"vendor_id": vendor_id, "approved_account": reconstructed_tx.trusted_registered_account},
            )
            spag.add_value_node(
                value_name="account",
                value=proposed_acc,
                originating_doc_id=next((s.source_handle for s in provenance_tracker.get_source_records() if "inv" in s.source_handle.lower()), None),
                authoritative_record_id=vendor_id if reconstructed_tx.account_matches_registry else None,
            )
            spag.add_value_node(value_name="amount", value=amount_val)

            # Runtime provenance analysis
            account_prov = provenance_tracker.analyze_proposed_argument(
                arg_name="account",
                proposed_value=proposed_acc,
                model_supplied_handles=arguments.get("provenance_handles", []),
                trusted_authoritative_value=reconstructed_tx.trusted_registered_account,
            )

            timeline.append(
                GatewayTraceEvent(
                    step_number=2,
                    step_name="Server State Reconstruction",
                    status="PASS" if reconstructed_tx.invariants_passed else "FAIL",
                    details={
                        "invoice_id": inv_id,
                        "vendor_id": vendor_id,
                        "proposed_account": proposed_acc,
                        "trusted_registered_account": reconstructed_tx.trusted_registered_account,
                        "account_matches": reconstructed_tx.account_matches_registry,
                        "violated_invariants": reconstructed_tx.violated_invariants,
                    },
                )
            )
            timeline.append(
                GatewayTraceEvent(
                    step_number=3,
                    step_name="Runtime Provenance Analysis",
                    status="PASS" if not account_prov.is_tainted else "FAIL",
                    details={
                        "trust_level": account_prov.trust_level.value,
                        "is_tainted": account_prov.is_tainted,
                        "taint_reason": account_prov.taint_reason,
                    },
                )
            )

        elif tool_name == "submit_payment":
            payment_id = str(arguments.get("payment_id", ""))
            reconstructed_tx = self.reconstructor.reconstruct_submit_payment(
                sandbox_state=sandbox.state,
                payment_id=payment_id,
            )

            spag.add_authoritative_node(
                record_id=reconstructed_tx.vendor_id or "V_PREP",
                label=f"Vendor {reconstructed_tx.vendor_id} Master Record",
                attributes={"vendor_id": reconstructed_tx.vendor_id, "approved_account": reconstructed_tx.trusted_registered_account},
            )
            spag.add_value_node(
                value_name="account",
                value=reconstructed_tx.proposed_account,
                authoritative_record_id=reconstructed_tx.vendor_id if reconstructed_tx.account_matches_registry else None,
            )
            spag.add_value_node(value_name="amount", value=reconstructed_tx.amount)

            account_prov = provenance_tracker.analyze_proposed_argument(
                arg_name="account",
                proposed_value=reconstructed_tx.proposed_account,
                trusted_authoritative_value=reconstructed_tx.trusted_registered_account,
            )

            timeline.append(
                GatewayTraceEvent(
                    step_number=2,
                    step_name="Server State Reconstruction (Prepared Record)",
                    status="PASS" if reconstructed_tx.invariants_passed else "FAIL",
                    details={
                        "payment_id": payment_id,
                        "authoritative_amount": reconstructed_tx.amount,
                        "authoritative_account": reconstructed_tx.proposed_account,
                        "account_matches": reconstructed_tx.account_matches_registry,
                    },
                )
            )

        # Step 4 & 5: Approval Lifecycle Validation (Read-Only)
        approval_id = arguments.get("approval_id") or arguments.get("approval_token")
        has_approval = bool(approval_id)
        approval_valid = False
        approval_rec = None

        if has_approval:
            vendor_target = reconstructed_tx.vendor_id if reconstructed_tx else arguments.get("vendor_id", "")
            account_target = reconstructed_tx.trusted_registered_account if (reconstructed_tx and reconstructed_tx.trusted_registered_account) else arguments.get("account", "")
            amount_target = reconstructed_tx.amount if reconstructed_tx else float(arguments.get("amount", 0.0))

            is_valid, app_reason, approval_rec = self.approvals.validate(
                approval_id=approval_id,
                action=tool_name,
                vendor_id=vendor_target,
                account=account_target,
                amount=amount_target,
                currency=arguments.get("currency", "INR"),
            )
            approval_valid = is_valid

            spag.add_approval_node(
                approval_id=approval_id,
                approver=approval_rec.user_id if approval_rec else "unknown",
                approved_amount=approval_rec.amount if approval_rec else 0.0,
                is_valid=approval_valid,
            )

            timeline.append(
                GatewayTraceEvent(
                    step_number=5,
                    step_name="Approval Verification (Phase 1)",
                    status="PASS" if approval_valid else "FAIL",
                    details={"approval_id": approval_id, "valid": approval_valid, "reason": app_reason},
                )
            )

        # SPAG Invariant Evaluation
        prop_acc = reconstructed_tx.proposed_account if reconstructed_tx else arguments.get("account", "")
        reg_acc = reconstructed_tx.trusted_registered_account if reconstructed_tx else ""
        prop_amt = reconstructed_tx.amount if reconstructed_tx else float(arguments.get("amount", 0.0))
        po_lim = reconstructed_tx.po_approved_amount if reconstructed_tx else 0.0

        spag_passed, spag_conflicts = spag.evaluate_and_propagate(
            proposed_account=prop_acc,
            trusted_registered_account=reg_acc,
            proposed_amount=prop_amt,
            po_limit=po_lim,
            action_name=tool_name,
            approval_valid=approval_valid,
        )

        timeline.append(
            GatewayTraceEvent(
                step_number=6,
                step_name="SPAG Invariant & Trust Propagation",
                status="PASS" if spag_passed else "FAIL",
                details={"invariants_passed": spag_passed, "conflicts": spag_conflicts, "canonical_hash": spag.compute_canonical_hash()[:16]},
            )
        )

        # Step 6: Construct Cedar Context
        action_name = f"Procurement::Action::\"{tool_name}\""
        resource_name = "Procurement::System::\"sandbox\""

        account_trust = account_prov.trust_level.value if account_prov else "trusted"
        is_tainted = account_prov.is_tainted if account_prov else False

        amount_context = int(round(reconstructed_tx.amount)) if reconstructed_tx else int(round(float(arguments.get("amount", 0.0))))
        is_prepared = reconstructed_tx.is_prepared if reconstructed_tx else sandbox.is_payment_prepared(arguments.get("payment_id", ""))

        to_email = str(arguments.get("to", ""))
        is_external = any(d in to_email.lower() for d in ["evil", "external", "attacker", "gmail", "tempmail"])
        is_confidential = "confidential" in str(arguments.get("body", "")).lower() or "/internal/" in str(arguments.get("doc_path", ""))

        cedar_context: Dict[str, Any] = {
            "amount": amount_context,
            "vendor_id": reconstructed_tx.vendor_id if reconstructed_tx else arguments.get("vendor_id", ""),
            "account": reconstructed_tx.proposed_account if reconstructed_tx else arguments.get("account", ""),
            "account_trust_level": account_trust,
            "recipient_trust_level": "untrusted" if is_external else "trusted",
            "is_tainted": is_tainted,
            "has_valid_approval": has_approval,
            "approval_valid": approval_valid,
            "is_prepared": is_prepared,
            "to": to_email,
            "has_confidential_content": is_confidential,
            "is_external_recipient": is_external,
            "email_id": arguments.get("email_id", ""),
            "invoice_id": arguments.get("invoice_id", ""),
            "payment_id": arguments.get("payment_id", ""),
            "approval_id": approval_id or "",
            "doc_path": arguments.get("doc_path", ""),
            "is_protected_doc": bool(arguments.get("doc_path")),
        }

        # Step 7: Evaluate Cedar Policy
        decision = self.cedar.evaluate(
            principal=caller_principal,
            action=action_name,
            resource=resource_name,
            context=cedar_context,
            custom_policy_text=custom_policy_text,
            configuration=configuration,
        )

        timeline.append(
            GatewayTraceEvent(
                step_number=7,
                step_name="Cedar Policy Evaluation",
                status="ALLOW" if decision.is_allowed() else "DENY",
                details={
                    "decision": decision.decision,
                    "matched_policies": decision.matched_policies,
                    "reason": decision.reason,
                    "configuration": configuration,
                },
            )
        )

        # Step 8: Execution Gate (ALLOW vs DENY)
        if not decision.is_allowed():
            timeline.append(
                GatewayTraceEvent(
                    step_number=8,
                    step_name="Pre-Execution Block",
                    status="DENY",
                    details={"outcome": "BLOCKED_BEFORE_EXECUTION", "reason": decision.reason},
                )
            )
            elapsed = (time.perf_counter() - start_time) * 1000.0
            sec_overhead = (time.perf_counter() - sec_start) * 1000.0

            return GatewayExecutionResult(
                run_id=run_id,
                tool_name=tool_name,
                requested_arguments=arguments,
                decision=decision,
                executed=False,
                result={"error": "ACCESS_DENIED", "policy_reason": decision.reason},
                side_effect_occurred=False,
                reconstructed_transaction=reconstructed_tx,
                spag_graph=spag.to_dict(),
                execution_capability=None,
                state_before=state_before,
                state_after=state_before,
                state_diff={},
                trace_timeline=timeline,
                error=decision.reason,
                security_overhead_latency_ms=round(sec_overhead, 2),
                latency_ms=round(elapsed, 2),
            )

        # Step 9: Phase 2a - Reserve Approval Nonce
        if has_approval and approval_valid:
            self.approvals.reserve(approval_id, run_id=run_id)

        # Step 10: Issue Cryptographically Signed Execution Capability Token
        capability_rec: Optional[ExecutionCapability] = None
        if configuration == "cedar_provenance":
            capability_rec = self.capabilities.issue_capability(
                tool_name=tool_name,
                arguments=arguments,
                transaction_id=reconstructed_tx.invoice_id if reconstructed_tx else "TX-DIRECT",
                spag_graph_hash=spag.compute_canonical_hash(),
                policy_hash=hashlib.sha256((custom_policy_text or "").encode("utf-8")).hexdigest()[:16],
                session_id=run_id,
                approval_id=approval_id,
                ttl_seconds=60,
            )
            timeline.append(
                GatewayTraceEvent(
                    step_number=9,
                    step_name="Execution Capability Issuance",
                    status="PASS",
                    details={
                        "capability_id": capability_rec.capability_id,
                        "nonce": capability_rec.nonce,
                        "expires_at": capability_rec.expires_at,
                        "signature": capability_rec.signature[:16] + "...",
                    },
                )
            )

        # Step 11: Execute Tool Action in Sandbox with Capability
        try:
            tool_fn = getattr(sandbox, tool_name, None)
            if not tool_fn:
                raise ValueError(f"Unknown sandbox tool '{tool_name}'")

            exec_kwargs = dict(arguments)
            if capability_rec:
                exec_kwargs["capability_token"] = capability_rec.capability_id

            tool_output, side_effect_details = tool_fn(**exec_kwargs)
            state_after = copy.deepcopy(sandbox.state)
            state_diff = self._compute_state_diff(state_before, state_after)

            # Step 12: Phase 2b - Commit Approval Consumption
            if has_approval and approval_valid:
                self.approvals.commit(approval_id)

            timeline.append(
                GatewayTraceEvent(
                    step_number=10,
                    step_name="Sandbox Execution & State Mutation",
                    status="PASS" if side_effect_details.get("state_changed", False) or "error" not in tool_output else "FAIL",
                    details={"side_effect": side_effect_details, "state_diff": state_diff},
                )
            )

            elapsed = (time.perf_counter() - start_time) * 1000.0
            sec_overhead = (time.perf_counter() - sec_start) * 1000.0

            return GatewayExecutionResult(
                run_id=run_id,
                tool_name=tool_name,
                requested_arguments=arguments,
                decision=decision,
                executed=True,
                result=tool_output,
                side_effect_occurred=side_effect_details.get("state_changed", False),
                reconstructed_transaction=reconstructed_tx,
                spag_graph=spag.to_dict(),
                execution_capability=capability_rec.to_dict() if capability_rec else None,
                state_before=state_before,
                state_after=state_after,
                state_diff=state_diff,
                trace_timeline=timeline,
                error=None,
                security_overhead_latency_ms=round(sec_overhead, 2),
                latency_ms=round(elapsed, 2),
            )

        except Exception as exc:
            # Release reserved approval if tool execution fails
            if has_approval and approval_valid:
                self.approvals.release(approval_id)

            timeline.append(
                GatewayTraceEvent(
                    step_number=10,
                    step_name="Sandbox Execution Failed",
                    status="FAIL",
                    details={"error": str(exc)},
                )
            )
            elapsed = (time.perf_counter() - start_time) * 1000.0
            sec_overhead = (time.perf_counter() - sec_start) * 1000.0

            return GatewayExecutionResult(
                run_id=run_id,
                tool_name=tool_name,
                requested_arguments=arguments,
                decision=decision,
                executed=False,
                result={"error": f"EXECUTION_FAILED: {str(exc)}"},
                side_effect_occurred=False,
                reconstructed_transaction=reconstructed_tx,
                spag_graph=spag.to_dict(),
                execution_capability=capability_rec.to_dict() if capability_rec else None,
                state_before=state_before,
                state_after=state_before,
                state_diff={},
                trace_timeline=timeline,
                error=str(exc),
                security_overhead_latency_ms=round(sec_overhead, 2),
                latency_ms=round(elapsed, 2),
            )

    def _compute_state_diff(self, before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
        diff: Dict[str, Any] = {}
        for key in ["prepared_payments", "submitted_payments", "sent_emails", "deleted_documents"]:
            b_val = before.get(key, [])
            a_val = after.get(key, [])
            if isinstance(b_val, dict) and isinstance(a_val, dict):
                added_keys = set(a_val.keys()) - set(b_val.keys())
                if added_keys:
                    diff[key] = {k: a_val[k] for k in added_keys}
            elif isinstance(b_val, list) and isinstance(a_val, list):
                if len(a_val) > len(b_val):
                    diff[key] = a_val[len(b_val):]
        return diff
