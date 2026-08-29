# Architecture Decisions Record (ADR)

## ADR-001: Pre-Execution Authorization Order
**Context:** In tool-using agents, sensitive operations (payments, document deletions, external communication) must never execute before policy evaluation.
**Decision:** All sensitive tool requests must strictly follow:
```text
Agent tool request
    → Argument normalization
    → Provenance attachment (source tags & taint tracking)
    → Identity & Server-Side Approval verification
    → Cedar authorization decision (ALLOW or DENY)
    → Record audit event (Attempt + Authorization Decision)
    → Tool execution ONLY if ALLOW
    → Record resulting side-effect state
```
If DENY is returned, tool execution is bypassed entirely and a structured Policy Denied response is returned to the agent.

---

## ADR-002: Official Cedar CLI and AgentCore Policy Integration
**Context:** Handwritten policy evaluators cannot claim exact Cedar semantics or equivalence to AgentCore Policy.
**Decision:** Policy evaluation and schema validation use the official Cedar engine (`cedar` / `cedar-policy-cli` and standard Cedar AST/JSON formats). All policies are stored in `.cedar` files with an official Cedar schema (`schema.cedarschema.json`).

---

## ADR-003: Server-Side Non-Forgeable, Expiring Approvals
**Context:** AI agents executing prompt injection payloads can hallucinate or fabricate approval strings (e.g. `"approval_id": "APPROVED-123"`).
**Decision:** Approvals are managed strictly server-side by an `ApprovalAuthority` ledger. Each approval record contains:
- `approval_id`: Secure cryptographic UUID
- `user_id`: Authorized principal
- `action`: Specific tool action (e.g. `submit_payment`, `delete_document`)
- `vendor_id`: Target vendor
- `account`: Target bank/IBAN account
- `amount` & `currency`: Exact monetary bounds
- `created_at` & `expires_at`: Strict temporal validity window (TTL)
- `nonce`: Single-use token (invalidated upon payment submission to prevent replay)
- `status`: `PENDING` | `APPROVED` | `REJECTED` | `USED` | `EXPIRED`
- `digest`: HMAC-SHA256 integrity signature verifying server issuance

Any tool invocation referencing an unapproved, expired, reused, or parameter-mismatched approval is rejected.

---

## ADR-004: Explicit Structured Provenance vs Model Reasoning
**Context:** Inferring a language model's internal causal reasoning is nondeterministic and unverifiable.
**Decision:** Provenance is tracked via explicit, verifiable structured metadata attached to inputs and propagated through tool invocations:
- Source IDs and Source Types (`system`, `direct_user`, `email`, `invoice`, `document`, `memory`, `tool_response`)
- Trust Levels: `trusted`, `user_authorized`, `untrusted`, `derived_untrusted`
- Taint Propagation: When untrusted inputs (e.g., an invoice body) supply sensitive tool arguments (e.g., `account` or `recipient`), the argument is flagged as `derived_untrusted`.
- Cedar policies evaluate this structured provenance field in context.

---

## ADR-005: Security Configuration Matrix
**Context:** Evaluating protection efficacy requires controlled comparison across identical tasks and payloads.
**Decision:** 4 distinct configurations:
1. `unprotected`: No security system prompt, no Cedar gateway, tool calls allowed.
2. `prompt_only`: Hardened system prompt instructing agent to reject untrusted instructions, no deterministic policy enforcement.
3. `cedar_only`: Gateway Cedar enforcement of coarse rules (amount limits <= ₹50,000, valid approval presence, action order), but without instruction provenance inspection.
4. `cedar_provenance`: Full defense-in-depth: Cedar enforcement + instruction provenance + taint boundaries + server-side approval verification.

---

## ADR-006: Separation of Local Validation vs Live Model Evaluations
**Context:** Deterministic local harness execution tests software mechanics, but cannot measure LLM prompt injection vulnerability.
**Decision:** All results and logs are strictly partitioned:
- **Local Structural Validation**: Verifies tools, policy gates, evaluators, and replay mechanics deterministically.
- **Live Model Evaluations**: Measures actual LLM susceptibility across repetitions ($N=40 \times 4 \times 2 = 320$ runs) with immutable experiment manifests capturing model ID, temperature, dataset hash, and prompt hash.

---

## ADR-007: Agentic Policy Repair Loop with Regression Testing
**Context:** Static policies cannot adapt to zero-day injection techniques discovered during red-teaming.
**Decision:** When an attack succeeds against existing policies:
1. Forensic agent analyzes trace and produces a structured Violation Report.
2. Policy Repair Agent synthesizes a candidate Cedar rule.
3. Official Cedar validator checks syntax and schema compatibility.
4. Regression suite executes:
   - Target attack scenario (must now be blocked)
   - Same-category attack scenarios (evaluates generalization)
   - All benign control scenarios (must preserve legitimate task completion, $\text{FPR} < 5\%$)
5. Patch is presented as a candidate recommendation with full empirical evidence. Never automatically activated without validation.
