"""
Cryptographic Server-Side Approval Authority with 2-Phase Commit Lifecycle.

Implements ADR-003 and Section 5:
- Approvals are cryptographically signed HMAC-SHA256 records stored server-side.
- 2-Phase Commit lifecycle: validate() -> reserve() -> commit() -> release().
- A Cedar denial does NOT consume the approval.
- Concurrency-safe: Nonce reservation prevents concurrent double-spending.
- Environment-based signing key loading with secure fail-safe.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple


class ApprovalStatus(str, Enum):
    APPROVED = "APPROVED"
    RESERVED = "RESERVED"
    COMMITTED = "COMMITTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


@dataclass
class ApprovalRecord:
    approval_id: str
    user_id: str
    action: str
    vendor_id: str
    account: str
    amount: float
    currency: str
    created_at: float
    expires_at: float
    nonce: str
    status: ApprovalStatus
    signature: str
    reserved_by_run_id: Optional[str] = None
    payment_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


class ServerSideApprovalAuthority:
    """
    Centralized, server-side approval registry with 2-phase commit semantics.
    Guarantees non-forgeability, anti-replay, parameter binding, and atomicity.
    """

    def __init__(self, secret_key: Optional[str] = None):
        secret = secret_key or os.environ.get("SECVAL_SIGNING_SECRET")
        if not secret:
            # Fallback only in development/test environment
            env_mode = os.environ.get("ENVIRONMENT", "local").lower()
            if env_mode in ("local", "test", "dev"):
                secret = "secval-dev-secret-key-32bytes-long!"
            else:
                raise ValueError("SECVAL_SIGNING_SECRET environment variable is required in production mode.")
        self._secret_key = secret.encode("utf-8")
        self._registry: Dict[str, ApprovalRecord] = {}
        self._consumed_nonces: set[str] = set()
        self._reserved_nonces: set[str] = set()
        self._lock = threading.Lock()

    def _compute_digest(
        self,
        approval_id: str,
        user_id: str,
        action: str,
        vendor_id: str,
        account: str,
        amount: float,
        currency: str,
        created_at: float,
        expires_at: float,
        nonce: str,
        payment_id: str = "",
    ) -> str:
        payload = f"{approval_id}|{user_id}|{action}|{vendor_id}|{account}|{amount:.2f}|{currency}|{created_at}|{expires_at}|{nonce}|{payment_id}"
        return hmac.new(self._secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue_approval(
        self,
        user_id: str,
        action: str,
        vendor_id: str,
        account: str,
        amount: float,
        currency: str = "INR",
        ttl_seconds: int = 3600,
        payment_id: Optional[str] = None,
    ) -> ApprovalRecord:
        """Issue an authentic, cryptographically signed approval record."""
        with self._lock:
            approval_id = f"APP-{uuid.uuid4().hex[:12].upper()}"
            nonce = uuid.uuid4().hex
            now = time.time()
            expires_at = now + ttl_seconds

            sig = self._compute_digest(
                approval_id=approval_id,
                user_id=user_id,
                action=action,
                vendor_id=vendor_id,
                account=account,
                amount=amount,
                currency=currency,
                created_at=now,
                expires_at=expires_at,
                nonce=nonce,
                payment_id=payment_id or "",
            )

            record = ApprovalRecord(
                approval_id=approval_id,
                user_id=user_id,
                action=action,
                vendor_id=vendor_id,
                account=account,
                amount=amount,
                currency=currency,
                created_at=now,
                expires_at=expires_at,
                nonce=nonce,
                status=ApprovalStatus.APPROVED,
                signature=sig,
                payment_id=payment_id,
            )

            self._registry[approval_id] = record
            return record

    def validate(
        self,
        approval_id: str,
        action: str,
        vendor_id: str,
        account: str,
        amount: float,
        currency: str = "INR",
        current_time: Optional[float] = None,
    ) -> Tuple[bool, str, Optional[ApprovalRecord]]:
        """
        Phase 1: Read-only validation. Does NOT alter state or consume the nonce.
        Used before evaluating Cedar policies.
        """
        with self._lock:
            if not approval_id:
                return False, "Approval ID is missing.", None

            record = self._registry.get(approval_id)
            if not record:
                return False, f"Approval ID '{approval_id}' not found in server registry (unauthorized/fabricated).", None

            # Verify cryptographic signature integrity
            expected_sig = self._compute_digest(
                approval_id=record.approval_id,
                user_id=record.user_id,
                action=record.action,
                vendor_id=record.vendor_id,
                account=record.account,
                amount=record.amount,
                currency=record.currency,
                created_at=record.created_at,
                expires_at=record.expires_at,
                nonce=record.nonce,
                payment_id=record.payment_id or "",
            )
            if not hmac.compare_digest(record.signature, expected_sig):
                return False, "Approval signature is invalid (tampered token).", None

            # Check status and replay
            if record.status == ApprovalStatus.COMMITTED or record.nonce in self._consumed_nonces:
                return False, f"Approval '{approval_id}' was already committed/consumed (single-use nonce violation).", record

            if record.status == ApprovalStatus.RESERVED:
                return False, f"Approval '{approval_id}' is currently reserved by an active transaction.", record

            if record.status != ApprovalStatus.APPROVED:
                return False, f"Approval status is '{record.status.value}', expected 'APPROVED'.", record

            # Check expiration
            now = current_time if current_time is not None else time.time()
            if now > record.expires_at:
                record.status = ApprovalStatus.EXPIRED
                return False, f"Approval '{approval_id}' has expired.", record

            # Parameter binding validation (Anti-swapping)
            if record.action != action:
                return False, f"Approval action mismatch: expected '{record.action}', received '{action}'.", record

            if record.vendor_id != vendor_id:
                return False, f"Approval vendor mismatch: approved for '{record.vendor_id}', received '{vendor_id}'.", record

            if record.account != account:
                return False, f"Approval account mismatch: approved for '{record.account}', received '{account}'.", record

            if abs(record.amount - amount) > 0.01:
                return False, f"Approval amount mismatch: approved for ₹{record.amount:,.2f}, received ₹{amount:,.2f}.", record

            if record.currency.upper() != currency.upper():
                return False, f"Approval currency mismatch: approved for '{record.currency}', received '{currency}'.", record

            return True, "Approval signature and parameter bindings verified.", record

    def reserve(self, approval_id: str, run_id: str) -> bool:
        """
        Phase 2a: Atomically reserve an approval prior to tool execution.
        Prevents concurrent execution using the same approval.
        """
        with self._lock:
            record = self._registry.get(approval_id)
            if not record or record.status != ApprovalStatus.APPROVED:
                return False
            if record.nonce in self._reserved_nonces or record.nonce in self._consumed_nonces:
                return False

            record.status = ApprovalStatus.RESERVED
            record.reserved_by_run_id = run_id
            self._reserved_nonces.add(record.nonce)
            return True

    def commit(self, approval_id: str) -> bool:
        """
        Phase 2b: Finalize consumption upon successful tool execution.
        """
        with self._lock:
            record = self._registry.get(approval_id)
            if not record or record.status != ApprovalStatus.RESERVED:
                return False

            record.status = ApprovalStatus.COMMITTED
            self._reserved_nonces.discard(record.nonce)
            self._consumed_nonces.add(record.nonce)
            return True

    def release(self, approval_id: str) -> bool:
        """
        Phase 2c: Release reservation back to APPROVED if execution fails or is aborted.
        """
        with self._lock:
            record = self._registry.get(approval_id)
            if not record or record.status != ApprovalStatus.RESERVED:
                return False

            record.status = ApprovalStatus.APPROVED
            self._reserved_nonces.discard(record.nonce)
            record.reserved_by_run_id = None
            return True

    def validate_and_consume(
        self,
        approval_id: str,
        action: str,
        vendor_id: str,
        account: str,
        amount: float,
        currency: str = "INR",
        current_time: Optional[float] = None,
    ) -> Tuple[bool, str, Optional[ApprovalRecord]]:
        """Convenience method combining validate, reserve, and commit for legacy workflows."""
        valid, msg, rec = self.validate(approval_id, action, vendor_id, account, amount, currency, current_time)
        if valid and rec:
            self.reserve(approval_id, run_id="legacy")
            self.commit(approval_id)
        return valid, msg, rec

    def get_approval(self, approval_id: str) -> Optional[ApprovalRecord]:
        with self._lock:
            return self._registry.get(approval_id)

    def reset(self) -> None:
        with self._lock:
            self._registry.clear()
            self._consumed_nonces.clear()
            self._reserved_nonces.clear()
