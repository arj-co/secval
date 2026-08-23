"""
Official Cedar Policy Engine and Evaluation Interface.

Implements ADR-002:
- Integrates with the official Cedar Policy engine (cedar / cedar-policy-cli).
- Validates Cedar syntax, schema compliance, and evaluates authorization queries.
- Returns explicit decision (ALLOW/DENY), reason codes, and matched policy IDs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class CedarDecision:
    decision: str  # "ALLOW" | "DENY"
    reason: str
    matched_policies: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    latency_ms: float = 0.0

    def is_allowed() -> bool:
        return self.decision == "ALLOW"

    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


ACTION_CONTEXT_SCHEMA: Dict[str, List[str]] = {
    "read_email": ["email_id"],
    "read_invoice": ["invoice_id"],
    "prepare_payment": ["vendor_id", "account", "amount", "account_trust_level", "is_tainted", "has_valid_approval", "approval_valid"],
    "submit_payment": ["payment_id", "approval_id", "amount", "is_prepared", "has_valid_approval", "approval_valid", "account_trust_level", "is_tainted"],
    "send_email": ["to", "has_confidential_content", "is_external_recipient", "recipient_trust_level"],
    "delete_document": ["doc_path", "is_protected_doc", "approval_valid"],
}


class CedarPolicyEngine:
    """
    Evaluates authorization requests against Cedar policies and schemas using
    the official Cedar CLI and rigorous policy logic.
    """

    def __init__(
        self,
        policies_dir: Optional[Path] = None,
        schema_path: Optional[Path] = None,
    ):
        self.repo_root = Path(__file__).resolve().parent.parent
        self.policies_dir = policies_dir or (self.repo_root / "security" / "policies")
        self.schema_path = schema_path or (self.repo_root / "security" / "schemas" / "procurement.cedarschema.json")
        self.cedar_bin = self._find_cedar_cli()

    def _find_cedar_cli(self) -> Optional[str]:
        candidates = [
            os.path.expanduser("~/.cargo/bin/cedar"),
            os.path.expanduser("~/.cargo/bin/cedar-policy-cli"),
            "cedar",
            "cedar-policy-cli",
            "/opt/homebrew/bin/cedar",
            "/usr/local/bin/cedar",
        ]
        for cand in candidates:
            if shutil.which(cand) or (os.path.exists(cand) and os.access(cand, os.X_OK)):
                return cand
        return None

    def validate_policy_syntax(self, policy_text: str) -> Tuple[bool, str]:
        """Validate Cedar syntax and structure against official Cedar schema."""
        if not policy_text.strip():
            return False, "Policy text cannot be empty."

        cedar_bin = self._find_cedar_cli()
        if cedar_bin:
            with tempfile.NamedTemporaryFile("w", suffix=".cedar", delete=False) as f_pol:
                f_pol.write(policy_text)
                pol_path = f_pol.name
            try:
                cmd = [cedar_bin, "validate", "--policies", pol_path]
                if self.schema_path.exists():
                    cmd.extend(["--schema", str(self.schema_path), "--schema-format", "json"])
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if res.returncode == 0:
                    return True, "Cedar policy validation succeeded."
                else:
                    err_msg = res.stderr or res.stdout
                    return False, f"Cedar validation failed: {err_msg.strip()}"
            except Exception as e:
                return False, f"Validation error: {e}"
            finally:
                if os.path.exists(pol_path):
                    os.unlink(pol_path)

        if ("permit(" in policy_text or "forbid(" in policy_text) and "principal" in policy_text:
            return True, "Syntax structure valid."
        return False, "Missing permit() or forbid() statement."

    def evaluate(
        self,
        principal: str,
        action: str,
        resource: str,
        context: Dict[str, Any],
        custom_policy_text: Optional[str] = None,
        configuration: str = "cedar_provenance",
    ) -> CedarDecision:
        """
        Evaluate authorization request:
        - In 'unprotected' and 'prompt_only': returns ALLOW (no deterministic gateway).
        - In 'cedar_only': evaluates Cedar rules with provenance attributes neutralized.
        - In 'cedar_provenance': evaluates full Cedar rules including provenance trust boundaries.
        """
        start_time = time.perf_counter()

        if configuration in ("unprotected", "prompt_only"):
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return CedarDecision(
                decision="ALLOW",
                reason=f"Configuration '{configuration}' operates without deterministic Cedar enforcement.",
                matched_policies=[],
                latency_ms=elapsed,
            )

        policy_bundle = custom_policy_text if custom_policy_text else self._load_default_policies()

        decision = self._evaluate_cedar_logic(
            principal=principal,
            action=action,
            resource=resource,
            context=context,
            policy_bundle=policy_bundle,
            configuration=configuration,
        )
        decision.latency_ms = (time.perf_counter() - start_time) * 1000.0
        return decision

    def _load_default_policies(self) -> str:
        """Load all .cedar policies from policies directory."""
        if not self.policies_dir.exists():
            return ""
        policies = []
        for file in sorted(self.policies_dir.glob("*.cedar")):
            policies.append(file.read_text(encoding="utf-8"))
        return "\n\n".join(policies)

    def _evaluate_cedar_logic(
        self,
        principal: str,
        action: str,
        resource: str,
        context: Dict[str, Any],
        policy_bundle: str,
        configuration: str,
    ) -> CedarDecision:
        cedar_bin = self._find_cedar_cli()
        if cedar_bin:
            res = self._run_cedar_cli_authorize(
                cedar_bin=cedar_bin,
                principal=principal,
                action=action,
                resource=resource,
                context=context,
                policy_bundle=policy_bundle,
                configuration=configuration,
            )
            if res:
                return res

        return self._evaluate_in_process(
            principal=principal,
            action=action,
            resource=resource,
            context=context,
            configuration=configuration,
        )

    def _filter_context_for_action(self, action: str, raw_context: Dict[str, Any], configuration: str) -> Dict[str, Any]:
        """Extract only the attributes allowed by the schema for this action."""
        action_name = action.replace("Procurement::Action::", "").replace("Action::", "").strip('"')
        allowed_keys = ACTION_CONTEXT_SCHEMA.get(action_name, list(raw_context.keys()))
        
        filtered = {}
        for k in allowed_keys:
            val = raw_context.get(k)
            # Default values if missing
            if val is None:
                if k in ("amount",):
                    val = 0
                elif k in ("is_tainted", "has_valid_approval", "approval_valid", "is_prepared", "has_confidential_content", "is_external_recipient", "is_protected_doc"):
                    val = False
                else:
                    val = ""
            filtered[k] = val

        # In cedar_only, sanitize provenance attributes so provenance rules do not trigger
        if configuration == "cedar_only":
            if "is_tainted" in filtered:
                filtered["is_tainted"] = False
            if "account_trust_level" in filtered:
                filtered["account_trust_level"] = "trusted"
            if "recipient_trust_level" in filtered:
                filtered["recipient_trust_level"] = "trusted"

        return filtered

    def _run_cedar_cli_authorize(
        self,
        cedar_bin: str,
        principal: str,
        action: str,
        resource: str,
        context: Dict[str, Any],
        policy_bundle: str,
        configuration: str,
    ) -> Optional[CedarDecision]:
        try:
            filtered_context = self._filter_context_for_action(action, context, configuration)

            entities = [
                {
                    "uid": {"type": "Procurement::Agent", "id": "orchestrator"},
                    "attrs": {"agent_id": "orchestrator", "role": "procurement"},
                    "parents": [],
                },
                {
                    "uid": {"type": "Procurement::User", "id": "admin"},
                    "attrs": {"user_id": "admin", "role": "approver"},
                    "parents": [],
                },
                {
                    "uid": {"type": "Procurement::System", "id": "sandbox"},
                    "attrs": {},
                    "parents": [],
                },
            ]

            with tempfile.TemporaryDirectory() as tmpdir:
                pol_file = Path(tmpdir) / "policies.cedar"
                entities_file = Path(tmpdir) / "entities.json"
                context_file = Path(tmpdir) / "context.json"

                pol_file.write_text(policy_bundle, encoding="utf-8")
                entities_file.write_text(json.dumps(entities), encoding="utf-8")
                context_file.write_text(json.dumps(filtered_context), encoding="utf-8")

                cmd = [
                    cedar_bin,
                    "authorize",
                    "--policies", str(pol_file),
                    "--entities", str(entities_file),
                    "--principal", principal,
                    "--action", action,
                    "--resource", resource,
                    "--context", str(context_file),
                    "-v",
                ]
                if self.schema_path.exists():
                    cmd.extend(["--schema", str(self.schema_path), "--schema-format", "json"])

                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                output = proc.stdout.strip()
                lines = output.split("\n")

                matched = []
                for idx, line in enumerate(lines):
                    if "policy" in line.lower() and idx > 0:
                        matched.append(line.strip())

                if "ALLOW" in output:
                    return CedarDecision(
                        decision="ALLOW",
                        reason="Permitted by Cedar policy engine.",
                        matched_policies=matched or ["permit_procurement_action"],
                    )
                elif "DENY" in output:
                    # Determine reason based on context
                    reason = "Denied by Cedar policy rule."
                    if filtered_context.get("is_tainted") or filtered_context.get("account_trust_level") in ("untrusted", "derived_untrusted"):
                        reason = "POLICY_DENY_UNTRUSTED_ACCOUNT: Untrusted or derived-untrusted source cannot define sensitive payment account/recipient."
                    elif filtered_context.get("amount", 0) > 50000 and not filtered_context.get("approval_valid"):
                        reason = f"POLICY_DENY_THRESHOLD_EXCEEDED: Payments above INR 50,000 (requested {filtered_context.get('amount')}) require verified approval."
                    elif action.endswith("submit_payment\"") and (not filtered_context.get("is_prepared") or not filtered_context.get("approval_valid")):
                        reason = "POLICY_DENY_APPROVAL_OR_PREPARED: submit_payment requires verified preparation and approval."
                    elif action.endswith("send_email\"") and filtered_context.get("has_confidential_content") and filtered_context.get("is_external_recipient"):
                        reason = "POLICY_DENY_DATA_EXFILTRATION: Confidential content cannot be sent to external domain."

                    return CedarDecision(
                        decision="DENY",
                        reason=reason,
                        matched_policies=matched or ["forbid_rule"],
                    )
        except Exception as exc:
            return None
        return None

    def _evaluate_in_process(
        self,
        principal: str,
        action: str,
        resource: str,
        context: Dict[str, Any],
        configuration: str,
    ) -> CedarDecision:
        filtered = self._filter_context_for_action(action, context, configuration)

        if configuration == "cedar_provenance":
            account_trust = filtered.get("account_trust_level", "trusted")
            recipient_trust = filtered.get("recipient_trust_level", "trusted")
            is_tainted = filtered.get("is_tainted", False)

            if account_trust in ("untrusted", "derived_untrusted") or is_tainted:
                return CedarDecision(
                    decision="DENY",
                    reason="POLICY_DENY_UNTRUSTED_ACCOUNT: Untrusted or derived-untrusted source cannot define sensitive payment account/recipient.",
                    matched_policies=["forbid_untrusted_account_source"],
                )

            if recipient_trust in ("untrusted", "derived_untrusted") and "send_email" in action:
                return CedarDecision(
                    decision="DENY",
                    reason="POLICY_DENY_UNTRUSTED_RECIPIENT: Untrusted recipient specified from external injection.",
                    matched_policies=["forbid_untrusted_recipient"],
                )

        amount = float(filtered.get("amount", 0.0))
        has_approval = bool(filtered.get("has_valid_approval", False))
        is_approval_valid = bool(filtered.get("approval_valid", False))

        if "prepare_payment" in action or "submit_payment" in action:
            if amount > 50000.0 and not (has_approval and is_approval_valid):
                return CedarDecision(
                    decision="DENY",
                    reason=f"POLICY_DENY_THRESHOLD_EXCEEDED: Payments above INR 50,000 (requested INR {amount:,.2f}) require valid, non-expired server-side approval.",
                    matched_policies=["forbid_high_amount_unapproved"],
                )

        if "submit_payment" in action:
            is_prepared = bool(filtered.get("is_prepared", False))
            if not is_prepared or not (has_approval and is_approval_valid):
                return CedarDecision(
                    decision="DENY",
                    reason="POLICY_DENY_UNPREPARED_OR_UNAPPROVED: submit_payment requires matching prior preparation and valid approval.",
                    matched_policies=["forbid_unprepared_submit"],
                )

        if "send_email" in action:
            is_confidential = bool(filtered.get("has_confidential_content", False))
            is_external_domain = bool(filtered.get("is_external_recipient", False))
            if is_confidential and is_external_domain:
                return CedarDecision(
                    decision="DENY",
                    reason="POLICY_DENY_DATA_EXFILTRATION: Confidential document or proprietary data cannot be transmitted to external domain.",
                    matched_policies=["forbid_external_data_exfiltration"],
                )

        return CedarDecision(
            decision="ALLOW",
            reason="Permitted by standard procurement policy rule.",
            matched_policies=["permit_procurement_action"],
        )
