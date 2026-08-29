# System Architecture & Technical Design

## 1. Architectural Topology

The SecVal platform operates on a defense-in-depth pipeline where sensitive agent tool requests are intercepted, decorated with instruction provenance, evaluated against server-side approvals and official Cedar policies, and executed only upon explicit cryptographic and policy permit.

```text
┌─────────────────────────┐
│     User Task Input     │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐     ┌────────────────────────────────────┐
│    Procurement Agent    │ ──> │   Untrusted Document / Invoice     │
│   (Tool-Calling LLM)    │ <── │ (Indirect Prompt Injection Source) │
└────────────┬────────────┘     └────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────┐
│             Pre-Execution Gateway Interceptor          │
│ 1. Normalize Tool Arguments                            │
│ 2. Provenance Tracker & Taint Analysis                 │
│ 3. Server-Side Nonce-Bound Approval Verification       │
└────────────┬───────────────────────────────────────────┘
             │
             ▼
┌────────────────────────────────────────────────────────┐
│             Amazon Bedrock AgentCore & Cedar           │
│           Official Cedar Policy Engine (CLI)           │
│        Evaluate: Principal, Action, Resource, Context  │
└────────────┬───────────────────────────────────────────┘
             │
      ┌──────┴──────┐
      │             │
   [DENY]        [ALLOW]
      │             │
      ▼             ▼
┌───────────┐ ┌──────────────────────────────────────────┐
│  Record   │ │        Synthetic Enterprise Sandbox      │
│  Blocked  │ │ 1. Execute Sandbox Tool Action           │
│   Event   │ │ 2. Mutate Ledger State                   │
│ (No Side  │ │ 3. Record State Side Effect Event        │
│  Effect)  │ └────────────────────┬─────────────────────┘
└───────────┘                      │
      │                            │
      └─────────────┬──────────────┘
                    ▼
┌────────────────────────────────────────────────────────┐
│               Ground-Truth Evaluator                   │
│ • Legitimate Task Completion (LTCR)                    │
│ • Unauthorized Action Attempted vs Completed           │
│ • Attack Success Rate (ASR) & Relative Reduction       │
└────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 Pre-Execution Policy Interceptor (`security/interceptor.py`)
All tool invocations route through `PolicyGatewayInterceptor.dispatch()`. The interceptor guarantees that:
- Arguments are normalized and vetted against reference purchase orders.
- Any attempt to invoke `submit_payment`, `prepare_payment`, `send_email`, or `delete_document` generates a pre-execution authorization check.
- If Cedar returns `DENY`, the tool function is never called, preventing any state corruption or ledger alteration.

### 2.2 Instruction & Argument Provenance Engine (`security/provenance/`)
- Every data artifact ingested during an agent session is assigned a `SourceMetadata` record with an explicit trust level (`trusted`, `user_authorized`, `untrusted`, `derived_untrusted`).
- When an untrusted source (such as an invoice remittance note or phishing email) supplies sensitive arguments (e.g. `account="ACC-ATTACKER-6666"`), the `ProvenanceTracker` flags the argument as `derived_untrusted` and `is_tainted=true`.
- Cedar context evaluates these provenance attributes to forbid untrusted modifications.

### 2.3 Cryptographic Server-Side Approvals (`services/approvals.py`)
- Approvals are not free-form strings that an agent can hallucinate.
- Approvals are stored in a server-side authority with HMAC-SHA256 integrity signatures, expiring TTLs, and single-use nonces.
- Replaying a consumed nonce or submitting an approval for a different vendor, account, or amount fails atomically.

### 2.4 Official Cedar Policy Engine (`security/cedar_engine.py`)
- Integrates directly with the official Cedar Policy engine binary (`cedar-policy-cli`).
- Evaluates `.cedar` policy bundles against the official JSON schema (`procurement.cedarschema.json`).
- Delivers deterministic sub-15ms enforcement decisions.

### 2.5 Agentic Policy Repair Loop (`security/repair/agent.py`)
- When an indirect prompt-injection attack bypasses an existing policy, the forensic agent generates a `ViolationReport`.
- A candidate Cedar rule is synthesized and validated via `cedar validate`.
- A dual-regression harness tests the candidate rule against the target attack, same-category attacks, and all benign controls to guarantee zero utility breakage before presenting a recommendation.
