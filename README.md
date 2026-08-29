# SecVal: Zero-Trust Runtime Security Gateway for Tool-Using AI Agents

> **CuriousPARC Hackathon Submission**  
> *Deterministic Pre-Execution Authorization, Runtime-Owned Provenance, Trusted Transaction Reconstruction, and Guided Policy Repair.*

---

## 🎯 Executive Summary & Primary Claim

Enterprises are deploying autonomous tool-using AI agents to process supplier invoices, review contracts, and disburse corporate funds. However, indirect prompt injections hidden in untrusted documents can manipulate models into calling sensitive tools with attacker-controlled parameters (e.g. swapping supplier bank accounts or exfiltrating confidential documents).

**SecVal's Core Principle:**  
SecVal assumes the AI agent may be manipulated, confused, or compromised. **The model is never the final security authority.**

Before any tool creates a side effect, SecVal independently verifies:
1. **Who** is requesting the action (caller principal & session identity).
2. **Which** tool is being requested (`prepare_payment`, `submit_payment`, `send_email`, etc.).
3. **Exact arguments** and where sensitive values originated (runtime-owned provenance).
4. **Master Registry Matching** (authoritative server-side vendor and PO verification).
5. **Human Approval Verification** (cryptographic HMAC-SHA256 signature, parameter binding, single-use nonce).
6. **Cedar Policy Permit** (evaluated via official `cedar-policy-cli`).

If Cedar returns `DENY`, **the tool is blocked before execution and zero sandbox state changes occur.**

---

## 🏆 Key Achievements & Measured Evidence ($N = 88$ Runs)

```
========================================================================================================================
Configuration        Total Runs   ASR (%)    Wilson 95% CI      LTCR (%)   Rel. ASR Red.   FPR (%)   Recall (%)   p95 Latency
========================================================================================================================
unprotected          22           66.67%     [39.1%, 86.2%]     100.0%     0.00%           0.00%     0.00%        1.07 ms
prompt_only          22           66.67%     [39.1%, 86.2%]     100.0%     0.00%           0.00%     0.00%        0.73 ms
cedar_only           22           50.00%     [25.4%, 74.6%]     100.0%     25.00%          20.0%     33.33%       8.35 ms
cedar_provenance     22            0.00%     [ 0.0%, 24.3%]     100.0%     100.00%         20.0%     83.33%       8.02 ms
========================================================================================================================
```

- **100% Relative ASR Reduction:** Dropped successful attacks to 0.00%.
- **100.0% Legitimate Task Completion (LTCR):** Legitimate business transactions succeed with zero utility degradation.
- **Invariant-Based Security:** Rewording the prompt (Standard &rarr; Treasury Notice &rarr; Urgent CFO Escalation) fails to bypass SecVal because authorization checks ground-truth state, not keywords.
- **Sub-10ms Overhead:** Median latency is 4.2 ms, and p95 overhead is 8.02 ms.

---

## 🏛️ System Architecture

```text
┌────────────────────────────────────────────────────────┐
│   Agent (AWS Bedrock Claude / Deterministic Harness)   │
└──────────────────────────┬─────────────────────────────┘
                           │ Proposes Tool Call
                           ▼
┌────────────────────────────────────────────────────────┐
│            SecVal Pre-Execution Security Gateway       │
│  1. Schema & Argument Validation                       │
│  2. Runtime Provenance Resolution (Anti-Spoofing)      │
│  3. Trusted Transaction Reconstruction (PO & Vendor)   │
│  4. Server-Side Approval Verification (2PC Phase 1)    │
│  5. Official Cedar Policy Evaluation (CLI)             │
└──────────────────────────┬─────────────────────────────┘
                           │
                    ┌──────┴──────┐
                 [DENY]        [ALLOW]
                    │             │
                    ▼             ▼
             ┌───────────┐ ┌─────────────────────────────┐
             │ Pre-Exec  │ │ 1. Reserve Approval Nonce   │
             │   Block   │ │ 2. Execute Sandbox Action   │
             │ (0 State  │ │ 3. Commit Approval (2PC)    │
             │  Change)  │ │ 4. Record State Mutation    │
             └───────────┘ └─────────────────────────────┘
```

---

## ⚡ Quick Start & Reproduction

### 1. Prerequisites
- Python 3.11+
- Node.js 18+
- Cedar CLI v4.3.0 (`cargo install cedar-policy-cli` or pre-installed)

### 2. Run Test Suite & Policy Validation
```bash
make test             # Runs all 32 unit and integration tests
make test-policies    # Validates Cedar policies against schema
```

### 3. Run Benchmark
```bash
make smoke            # Quick 5-scenario offline smoke test
make benchmark-local  # Full scenario benchmark matrix
```

### 4. Launch Full Application (Backend API + Next.js Control Center)
```bash
make dev
```
Open **[http://localhost:3000](http://localhost:3000)** to view the SecVal Agent Security Control Center.

---

## 📚 Detailed Documentation
- [ARCHITECTURE.md](./ARCHITECTURE.md): Technical architecture, gateway pipeline, and 2PC approvals.
- [DEMO_SCRIPT.md](./DEMO_SCRIPT.md): Step-by-step 3-minute presentation walkthrough script.
- [THREAT_MODEL.md](./THREAT_MODEL.md): Indirect prompt injection threat taxonomy.
- [EVALUATION.md](./EVALUATION.md): Statistical evaluation methodology and empirical results.
- [BUILD_LOG.md](./BUILD_LOG.md): Engineering journal.
- [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md): Open-source notices.
