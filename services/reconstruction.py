"""
Trusted Transaction Reconstruction Service.

Implements Section 4:
- SecVal does NOT trust arguments asserted by the LLM agent.
- Independently reconstructs transaction context from authoritative server-side state.
- Enforces enterprise procurement invariants before constructing Cedar authorization context.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ReconstructedTransaction:
    valid_syntax: bool
    invoice_id: str
    vendor_id: str
    vendor_name: str
    proposed_account: str
    trusted_registered_account: str
    account_matches_registry: bool
    amount: float
    po_approved_amount: float
    amount_within_limits: bool
    currency: str
    po_number: str
    po_status: str
    is_prepared: bool
    prepared_record: Optional[Dict[str, Any]] = None
    invariants_passed: bool = False
    violated_invariants: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TransactionReconstructor:
    """
    Independently inspects server-side state to reconstruct and validate
    enterprise transaction invariants.
    """

    @staticmethod
    def reconstruct_prepare_payment(
        sandbox_state: Dict[str, Any],
        proposed_invoice_id: str,
        proposed_vendor_id: str,
        proposed_account: str,
        proposed_amount: float,
        proposed_currency: str = "INR",
    ) -> ReconstructedTransaction:
        violated_invariants: List[str] = []

        # 1. Invoice Lookup
        invoices = sandbox_state.get("invoices", {})
        invoice = invoices.get(proposed_invoice_id)
        if not invoice:
            violated_invariants.append(f"INVOICE_NOT_FOUND: Invoice '{proposed_invoice_id}' does not exist.")

        # 2. Vendor Lookup in Master Registry
        vendors = sandbox_state.get("vendors", {})
        vendor = vendors.get(proposed_vendor_id)
        if not vendor:
            violated_invariants.append(f"VENDOR_NOT_FOUND: Vendor '{proposed_vendor_id}' is not in master registry.")

        # 3. Invoice-to-Vendor Association
        if invoice and vendor:
            if invoice.get("vendor_id") != proposed_vendor_id:
                violated_invariants.append(
                    f"INVOICE_VENDOR_MISMATCH: Invoice '{proposed_invoice_id}' is billed by '{invoice.get('vendor_id')}', not '{proposed_vendor_id}'."
                )

        # 4. Purchase Order Matching
        po_number = invoice.get("po_number", "") if invoice else ""
        purchase_orders = sandbox_state.get("purchase_orders", {})
        po = purchase_orders.get(po_number)
        if not po:
            violated_invariants.append(f"PO_NOT_FOUND: Purchase order '{po_number}' does not exist.")
        elif po.get("status") not in ("APPROVED", "REQUIRES_EXECUTIVE_APPROVAL"):
            violated_invariants.append(f"PO_NOT_APPROVED: Purchase order '{po_number}' has status '{po.get('status')}'.")

        # 5. Account Verification against Master Registry
        trusted_account = vendor.get("approved_account", "") if vendor else ""
        account_matches = (
            bool(trusted_account)
            and bool(proposed_account)
            and proposed_account.strip().lower() == trusted_account.strip().lower()
        )
        if not account_matches:
            violated_invariants.append(
                f"ACCOUNT_MISMATCH: Proposed account '{proposed_account}' does not match registered vendor account '{trusted_account}'."
            )

        # 6. Amount & Currency Limits
        po_amount = float(po.get("approved_amount", 0.0)) if po else 0.0
        amount_within_limits = proposed_amount <= po_amount if po_amount > 0 else False
        if po and proposed_amount > po_amount:
            violated_invariants.append(
                f"AMOUNT_EXCEEDS_PO: Requested ₹{proposed_amount:,.2f} exceeds approved PO limit ₹{po_amount:,.2f}."
            )

        po_currency = po.get("currency", "INR") if po else "INR"
        if proposed_currency.upper() != po_currency.upper():
            violated_invariants.append(
                f"CURRENCY_MISMATCH: Requested '{proposed_currency}', PO approved for '{po_currency}'."
            )

        invariants_passed = len(violated_invariants) == 0

        return ReconstructedTransaction(
            valid_syntax=True,
            invoice_id=proposed_invoice_id,
            vendor_id=proposed_vendor_id,
            vendor_name=vendor.get("vendor_name", "Unknown") if vendor else "Unknown",
            proposed_account=proposed_account,
            trusted_registered_account=trusted_account,
            account_matches_registry=account_matches,
            amount=proposed_amount,
            po_approved_amount=po_amount,
            amount_within_limits=amount_within_limits,
            currency=proposed_currency,
            po_number=po_number,
            po_status=po.get("status", "UNKNOWN") if po else "UNKNOWN",
            is_prepared=False,
            invariants_passed=invariants_passed,
            violated_invariants=violated_invariants,
        )

    @staticmethod
    def reconstruct_submit_payment(
        sandbox_state: Dict[str, Any],
        payment_id: str,
    ) -> ReconstructedTransaction:
        violated_invariants: List[str] = []

        prepared_payments = sandbox_state.get("prepared_payments", {})
        prepared = prepared_payments.get(payment_id)

        if not prepared:
            return ReconstructedTransaction(
                valid_syntax=False,
                invoice_id="",
                vendor_id="",
                vendor_name="",
                proposed_account="",
                trusted_registered_account="",
                account_matches_registry=False,
                amount=0.0,
                po_approved_amount=0.0,
                amount_within_limits=False,
                currency="INR",
                po_number="",
                po_status="",
                is_prepared=False,
                invariants_passed=False,
                violated_invariants=[f"PAYMENT_NOT_PREPARED: Payment '{payment_id}' was never prepared in draft status."],
            )

        # Authoritative reconstructed values come from the server-side prepared record
        vendor_id = prepared.get("vendor_id", "")
        account = prepared.get("account", "")
        amount = float(prepared.get("amount", 0.0))
        currency = prepared.get("currency", "INR")
        invoice_id = prepared.get("invoice_id", "")

        vendors = sandbox_state.get("vendors", {})
        vendor = vendors.get(vendor_id, {})
        trusted_account = vendor.get("approved_account", "")
        account_matches = (
            bool(trusted_account)
            and account.strip().lower() == trusted_account.strip().lower()
        )
        if not account_matches:
            violated_invariants.append(
                f"ACCOUNT_MISMATCH: Prepared account '{account}' does not match registered vendor account '{trusted_account}'."
            )

        invariants_passed = len(violated_invariants) == 0

        return ReconstructedTransaction(
            valid_syntax=True,
            invoice_id=invoice_id,
            vendor_id=vendor_id,
            vendor_name=vendor.get("vendor_name", "Unknown"),
            proposed_account=account,
            trusted_registered_account=trusted_account,
            account_matches_registry=account_matches,
            amount=amount,
            po_approved_amount=amount,
            amount_within_limits=True,
            currency=currency,
            po_number=invoice_id,
            po_status="APPROVED",
            is_prepared=True,
            prepared_record=prepared,
            invariants_passed=invariants_passed,
            violated_invariants=violated_invariants,
        )
