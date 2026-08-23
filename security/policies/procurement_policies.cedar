// ==============================================================================
// Zero Trust Procurement Agent Cedar Policy Bundle
// Implements ADR-001, ADR-002, ADR-003, ADR-004
// ==============================================================================

// Rule 1: Baseline Permit for Procurement Agent Actions
permit(
    principal,
    action in [
        Procurement::Action::"read_email",
        Procurement::Action::"read_invoice",
        Procurement::Action::"prepare_payment",
        Procurement::Action::"submit_payment",
        Procurement::Action::"send_email",
        Procurement::Action::"delete_document"
    ],
    resource
);

// Rule 2a: FORBID prepare_payment exceeding INR 50,000 without valid server-side approval
forbid(
    principal,
    action == Procurement::Action::"prepare_payment",
    resource
)
when {
    context.amount > 50000 && !(context.has_valid_approval && context.approval_valid)
};

// Rule 2b: FORBID submit_payment exceeding INR 50,000 without valid server-side approval
forbid(
    principal,
    action == Procurement::Action::"submit_payment",
    resource
)
when {
    context.amount > 50000 && !(context.has_valid_approval && context.approval_valid)
};

// Rule 3a: FORBID prepare_payment when bank account source is untrusted, derived_untrusted, or tainted
forbid(
    principal,
    action == Procurement::Action::"prepare_payment",
    resource
)
when {
    context.is_tainted == true ||
    context.account_trust_level == "untrusted" ||
    context.account_trust_level == "derived_untrusted"
};

// Rule 3b: FORBID submit_payment when bank account source is untrusted, derived_untrusted, or tainted
forbid(
    principal,
    action == Procurement::Action::"submit_payment",
    resource
)
when {
    context.is_tainted == true ||
    context.account_trust_level == "untrusted" ||
    context.account_trust_level == "derived_untrusted"
};

// Rule 4: FORBID submit_payment without verified prior prepare_payment and verified approval
forbid(
    principal,
    action == Procurement::Action::"submit_payment",
    resource
)
when {
    !context.is_prepared || !context.approval_valid
};

// Rule 5: FORBID external data exfiltration (confidential document sent to external domain)
forbid(
    principal,
    action == Procurement::Action::"send_email",
    resource
)
when {
    context.has_confidential_content == true && context.is_external_recipient == true
};

// Rule 6: FORBID deletion of protected enterprise documents without valid approval
forbid(
    principal,
    action == Procurement::Action::"delete_document",
    resource
)
when {
    context.is_protected_doc == true && !context.approval_valid
};
