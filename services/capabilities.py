"""
Cryptographically Signed Execution Capabilities.

Implements Phase 3:
- Cedar ALLOW alone does NOT execute sensitive tool operations.
- SecVal issues a short-lived, single-use, cryptographically signed capability token.
- Capability binds: tool, canonical arguments hash, transaction, SPAG graph hash, policy hash, approval, session, nonce, expiration.
- Sandbox tools strictly reject any side-effecting invocation lacking a valid, unconsumed capability token.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple


class CapabilityStatus(str, Enum):
    ISSUED = "ISSUED"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass
class ExecutionCapability:
    capability_id: str
    tool_name: str
    arguments_hash: str
    transaction_id: str
    spag_graph_hash: str
    policy_hash: str
    approval_id: Optional[str]
    session_id: str
    issued_at: float
    expires_at: float
    nonce: str
    status: CapabilityStatus
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


def canonical_arguments_hash(arguments: Dict[str, Any], tool_name: Optional[str] = None) -> str:
    """Produce a canonical SHA-256 hash of tool arguments with consistent default normalization."""
    # Exclude ephemeral capability_token or metadata arguments
    filtered = {
        k: v for k, v in arguments.items()
        if k not in ("capability_token", "capability_id", "provenance_handles", "source_ids")
    }

    # Normalize tool-specific defaults
    if tool_name == "prepare_payment":
        filtered.setdefault("currency", "INR")
        if "amount" in filtered:
            try:
                filtered["amount"] = float(filtered["amount"])
            except (ValueError, TypeError):
                pass
    elif tool_name == "submit_payment":
        filtered["approval_id"] = filtered.get("approval_id") or ""
    elif tool_name == "send_email":
        filtered["attachment_ids"] = filtered.get("attachment_ids") or []
    elif tool_name == "delete_document":
        filtered["approval_id"] = filtered.get("approval_id") or ""

    canonical_json = json.dumps(filtered, sort_keys=True, default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class CapabilityAuthority:
    """
    Issues and atomically verifies single-use execution capability tokens.
    """

    def __init__(self, secret_key: Optional[str] = None):
        secret = secret_key or os.environ.get("SECVAL_SIGNING_SECRET")
        if not secret:
            env_mode = os.environ.get("ENVIRONMENT", "local").lower()
            if env_mode in ("local", "test", "dev"):
                secret = "secval-capabilities-secret-key-32b!"
            else:
                raise ValueError("SECVAL_SIGNING_SECRET required for CapabilityAuthority in production.")
        self._secret_key = secret.encode("utf-8")
        self._registry: Dict[str, ExecutionCapability] = {}
        self._consumed_nonces: set[str] = set()
        self._lock = threading.Lock()

    def _compute_signature(
        self,
        capability_id: str,
        tool_name: str,
        arguments_hash: str,
        transaction_id: str,
        spag_graph_hash: str,
        policy_hash: str,
        approval_id: str,
        session_id: str,
        issued_at: float,
        expires_at: float,
        nonce: str,
    ) -> str:
        payload = (
            f"{capability_id}|{tool_name}|{arguments_hash}|{transaction_id}|"
            f"{spag_graph_hash}|{policy_hash}|{approval_id}|{session_id}|"
            f"{issued_at}|{expires_at}|{nonce}"
        )
        return hmac.new(self._secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue_capability(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        transaction_id: str,
        spag_graph_hash: str,
        policy_hash: str,
        session_id: str,
        approval_id: Optional[str] = None,
        ttl_seconds: int = 60,
    ) -> ExecutionCapability:
        """Issue a signed single-use execution capability token after authorization."""
        with self._lock:
            cap_id = f"CAP-{uuid.uuid4().hex[:12].upper()}"
            nonce = uuid.uuid4().hex
            now = time.time()
            expires_at = now + ttl_seconds
            args_hash = canonical_arguments_hash(arguments, tool_name=tool_name)

            sig = self._compute_signature(
                capability_id=cap_id,
                tool_name=tool_name,
                arguments_hash=args_hash,
                transaction_id=transaction_id,
                spag_graph_hash=spag_graph_hash,
                policy_hash=policy_hash,
                approval_id=approval_id or "",
                session_id=session_id,
                issued_at=now,
                expires_at=expires_at,
                nonce=nonce,
            )

            record = ExecutionCapability(
                capability_id=cap_id,
                tool_name=tool_name,
                arguments_hash=args_hash,
                transaction_id=transaction_id,
                spag_graph_hash=spag_graph_hash,
                policy_hash=policy_hash,
                approval_id=approval_id,
                session_id=session_id,
                issued_at=now,
                expires_at=expires_at,
                nonce=nonce,
                status=CapabilityStatus.ISSUED,
                signature=sig,
            )

            self._registry[cap_id] = record
            return record

    def verify_and_consume(
        self,
        capability_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        session_id: str,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, str, Optional[ExecutionCapability]]:
        """
        Atomically verify that capability is authentic, non-expired, matches tool/arguments/session,
        and consume its single-use nonce.
        """
        with self._lock:
            if not capability_id:
                return False, "Execution capability missing. Side-effecting tools require a signed capability token.", None

            record = self._registry.get(capability_id)
            if not record:
                return False, f"Capability '{capability_id}' not recognized (forged or unissued token).", None

            # Verify signature
            expected_sig = self._compute_signature(
                capability_id=record.capability_id,
                tool_name=record.tool_name,
                arguments_hash=record.arguments_hash,
                transaction_id=record.transaction_id,
                spag_graph_hash=record.spag_graph_hash,
                policy_hash=record.policy_hash,
                approval_id=record.approval_id or "",
                session_id=record.session_id,
                issued_at=record.issued_at,
                expires_at=record.expires_at,
                nonce=record.nonce,
            )
            if not hmac.compare_digest(record.signature, expected_sig):
                return False, "Capability signature invalid (tampered token).", None

            # Check single-use nonce
            if record.status == CapabilityStatus.CONSUMED or record.nonce in self._consumed_nonces:
                return False, f"Capability '{capability_id}' has already been consumed (replay attack prevented).", record

            if record.status != CapabilityStatus.ISSUED:
                return False, f"Capability status is '{record.status.value}', expected 'ISSUED'.", record

            # Check expiration
            now = current_time if current_time is not None else time.time()
            if now > record.expires_at:
                record.status = CapabilityStatus.EXPIRED
                return False, f"Capability '{capability_id}' expired at {record.expires_at} (current {now}).", record

            # Check session binding
            if record.session_id != session_id:
                return False, f"Capability session mismatch: issued for '{record.session_id}', presented in '{session_id}'.", record

            # Check tool binding
            if record.tool_name != tool_name:
                return False, f"Capability tool mismatch: issued for '{record.tool_name}', presented for '{tool_name}'.", record

            # Check exact argument hash binding (Anti argument swapping)
            current_args_hash = canonical_arguments_hash(arguments, tool_name=tool_name)
            if record.arguments_hash != current_args_hash:
                return False, "Capability arguments mismatch: tool arguments were modified after authorization.", record

            # Atomically consume
            record.status = CapabilityStatus.CONSUMED
            self._consumed_nonces.add(record.nonce)
            return True, "Capability verified and consumed.", record

    def get_capability(self, capability_id: str) -> Optional[ExecutionCapability]:
        with self._lock:
            return self._registry.get(capability_id)

    def reset(self) -> None:
        with self._lock:
            self._registry.clear()
            self._consumed_nonces.clear()
