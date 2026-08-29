# Build Log & Experiment Journal

## Project Overview
- **Project:** Automated Security Evaluation and Policy-Enforcement Platform for Tool-Using AI Agents (SecVal)
- **Target:** Evaluate indirect prompt-injection vulnerability across 4 security configurations, enforce deterministic pre-execution Cedar policies with instruction provenance, execute an Agentic Policy Repair Loop with regression testing, and provide a synchronized 4-way trace replay dashboard.

---

## Phase 1: Baseline Establishment & Attribution
- **Date/Time:** 2026-08-29
- **Actions:**
  - Authenticated GitHub CLI and verified user fork `arj-co/sample-zero-trust-procurement-bedrock-agentcore`.
  - Cloned fork, configured `upstream` remote to `https://github.com/aws-samples/sample-zero-trust-procurement-bedrock-agentcore.git`.
  - Created working branch `mvp/agent-security-benchmark`.
  - Created Python 3.11 virtual environment (`.venv`).
  - Fixed upstream test collection blockage (`app.run()` guarded with `__main__` in agent entrypoints) and string slicing in logging.
  - Ran offline unit test suite: **9/9 tests passed** (`pytest tests/unit/ -v`).
  - Created `ARCHITECTURE_DECISIONS.md` documenting the pre-execution authorization order, official Cedar engine integration, server-side approvals, provenance tracking, and the Agentic Policy Repair loop.
  - Created `THIRD_PARTY_NOTICES.md` with full attribution to AWS Samples, AgentDojo, Cedar Policy, and Agentic Security.
- **Git Commit:** `chore: establish upstream baseline`

---

## Phase 2: Local Synthetic Enterprise Tool Sandbox & Vertical Slice Gate
- **Actions:**
  - Implemented `services/sandbox.py` with 5 enterprise procurement tools (`read_email`, `read_invoice`, `prepare_payment`, `submit_payment`, `send_email`) returning structured output and side effect audit details.
  - Implemented `services/approvals.py` (`ServerSideApprovalAuthority`) with cryptographic HMAC signatures, parameter binding, and single-use anti-replay nonces.
  - Implemented `security/provenance/` (`ProvenanceTracker`, `SourceMetadata`, `TrustLevel`) with structured taint propagation.
  - Installed official Cedar Policy engine CLI (`cedar-policy-cli v4.3.0` via Cargo).
  - Created official Cedar schema `security/schemas/procurement.cedarschema.json` and zero-trust policies `security/policies/procurement_policies.cedar`. Verified with `cedar validate`.
  - Implemented `security/interceptor.py` enforcing pre-execution authorization.
  - Executed Vertical Slice Gate in `tests/unit/test_vertical_slice.py` (malicious invoice account swap blocked under Cedar+Provenance, permitted under unprotected, legitimate invoice succeeds). **Passed 3/3 tests**.
- **Git Commit:** `feat: add synthetic enterprise tool sandbox and vertical slice`

---

## Phase 3: Scenario Dataset & Benchmark Engine
- **Actions:**
  - Built `benchmark/factories/scenario_factory.py` generating 40 labelled scenarios across 5 categories (8 emails, 8 invoices, 8 documents, 8 approval bypass, 8 benign controls).
  - Stored version-controlled scenarios in `benchmark/scenarios/corpus/`.
  - Built `benchmark/evaluators/ground_truth.py` evaluating legitimate completion vs unauthorized security violations.
  - Built `benchmark/metrics/calculator.py` with Wilson score 95% confidence intervals, ASR, LTCR, Relative ASR reduction, Precision, Recall, and FPR.
  - Built `benchmark/runner.py` executing 4-way comparative experiments and writing immutable experiment manifests (`EXP-*_manifest.json`, `EXP-*_summary.csv`).

---

## Phase 4: Agentic Policy Repair Loop with Regression Testing
- **Actions:**
  - Implemented `security/repair/agent.py` (`AgenticPolicyRepairLoop`).
  - Automated forensic violation report generation, Cedar candidate rule synthesis, official Cedar syntax validation (`cedar validate`), and dual-regression testing (target attack, category attacks, and all 8 benign controls).
  - Validated with unit test `tests/unit/test_policy_repair.py` (**Passed 1/1 test, 0 benign regressions, status `RECOMMENDED`**).

---

## Phase 5: Measured Baseline Benchmark (320 Executions)
- **Execution:** `python -m benchmark.runner --all --reps 2`
- **Results:**
  - `unprotected`: ASR = **90.62%** [81.0%, 95.6% CI], LTCR = **100.0%**
  - `prompt_only`: ASR = **90.62%** [81.0%, 95.6% CI], LTCR = **100.0%**
  - `cedar_only`: ASR = **65.62%** [53.4%, 76.1% CI], Relative Reduction = **27.59%**
  - `cedar_provenance`: ASR = **12.50%** [6.5%, 22.8% CI], Relative Reduction = **86.21%**, FPR = **0.00%**, Recall = **78.12%**, p95 Latency = **11.66 ms**.
- **Persisted to:** `benchmark/results/EXP-2B00C977_manifest.json` and CSV report.

---

## Phase 6: FastAPI Backend & Next.js UI Dashboard
- **Actions:**
  - Built `backend/api/server.py` exposing scenarios, runs, experiments, policy inspection, and policy repair endpoints. Verified with `tests/integration/test_api.py` (**Passed 5/5 tests**).
  - Built `dashboard/` using Next.js, React, Lucide-React, and Recharts.
  - Implemented Synchronized 4-Way Trace Replay, Executive KPI ribbon, Attack Category charts, and the interactive Agentic Policy Repair loop panel.
  - Production build verified: `npm run build` compiled successfully.
  - Containerization: Created `docker-compose.yml`, `Dockerfile.api`, and `dashboard/Dockerfile`.
  - Makefile updated with all top-level developer and verification targets (`make test`, `make test-policies`, `make smoke`, `make benchmark-local`, `make api`, `make dashboard`, `make dev`, `make build`).

---

## Phase 7: Documentation & Deliverables
- **Documentation Files:**
  - `README.md`
  - `ARCHITECTURE.md`
  - `THREAT_MODEL.md`
  - `EVALUATION.md`
  - `DEMO_SCRIPT.md`
  - `ARCHITECTURE_DECISIONS.md`
  - `THIRD_PARTY_NOTICES.md`
  - `BUILD_LOG.md`
  - `.env.example`
