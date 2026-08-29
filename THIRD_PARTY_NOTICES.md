# Third-Party Notices and Open Source Attribution

This repository incorporates, adapts, and builds upon open-source software. All original licenses and copyright notices have been preserved.

---

## 1. AWS Zero Trust Procurement Bedrock AgentCore Sample
- **Upstream Repository:** [https://github.com/aws-samples/sample-zero-trust-procurement-bedrock-agentcore](https://github.com/aws-samples/sample-zero-trust-procurement-bedrock-agentcore)
- **License:** MIT-0 (MIT No Attribution)
- **Copyright:** Amazon.com, Inc. or its affiliates. All Rights Reserved.
- **Usage & Boundary:**
  - Used as the foundational infrastructure scaffolding for AgentCore Runtime, MCP Gateway configuration patterns, AWS CDK stacks, and baseline agent prototypes (`agents/orchestrator`, `agents/vendor`, `agents/approval`).
  - Adapted for offline local execution, pre-execution interception, and identity propagation.

---

## 2. AgentDojo Benchmark & Evaluation Principles
- **Upstream Repository:** [https://github.com/ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo)
- **License:** MIT License
- **Copyright:** (c) 2024 SPY LAB, ETH Zurich
- **Usage & Boundary:**
  - Conceptual design and evaluation methodology for indirect prompt-injection benchmarks, tool execution environments, and ground-truth validation criteria.
  - Custom procurement scenarios, provenance tracking, and policy-repair implementations are original works.

---

## 3. Agentic Security Reference Concepts
- **Upstream Repository:** [https://github.com/msoedov/agentic_security](https://github.com/msoedov/agentic_security)
- **License:** Apache License 2.0
- **Copyright:** (c) 2024 Agentic Security Authors
- **Usage & Boundary:**
  - Reference taxonomy for indirect prompt injection vectors and red-teaming categories.

---

## 4. Cedar Policy Language & Engine
- **Upstream Repository:** [https://github.com/cedar-policy/cedar](https://github.com/cedar-policy/cedar)
- **License:** Apache License 2.0
- **Copyright:** Amazon.com, Inc. or its affiliates. All Rights Reserved.
- **Usage & Boundary:**
  - Official Cedar Policy engine, schema definitions, and authorization evaluation used for deterministic access control.

---

## 5. Strands Agents SDK & Bedrock AgentCore
- **Packages:** `strands-agents`, `bedrock-agentcore`
- **License:** Apache License 2.0
- **Usage:** Agent orchestration, tool integration, and AgentCore runtime interfaces.

---

## Summary of Original Contributions
The following components are original additions to this repository:
1. **Instruction & Argument Provenance Engine** (`security/provenance/`)
2. **Pre-Execution Gateway Policy Interceptor** (`security/interceptor.py`)
3. **Deterministic Synthetic Enterprise Sandbox** (`services/sandbox.py`) with 5 core tools and server-side signed approvals (`services/approvals.py`)
4. **Labelled 40-Scenario Indirect Prompt-Injection Dataset** (`benchmark/scenarios/`)
5. **Agentic Policy Repair Loop** (`security/repair/`) with automated syntax validation and dual-regression verification
6. **Synchronized 4-Way Trace Replay Dashboard & Experiment Metrics API** (`dashboard/`, `backend/`)
7. **Ground-Truth Evaluator & Wilson Score Confidence Calculator** (`benchmark/evaluators/`, `benchmark/metrics/`)
