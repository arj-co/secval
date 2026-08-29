# Threat Model & Attack Surface

## 1. Threat Overview & Scope

Autonomous enterprise agents process untrusted semi-structured data (emails, invoices, attachments, web documents). When untrusted inputs contain natural language instructions, they can trigger **Indirect Prompt Injections (IPI)**, causing the model to deviate from user objectives and execute unauthorized tool actions.

---

## 2. Threat Actor Profiles

| Threat Actor | Vector | Objective | Capabilities |
|---|---|---|---|
| **Rogue Vendor / Malicious Payee** | Poisoned Invoices | Account Swap, Amount Inflation | Injects remittance instructions into invoice PDF notes or headers. |
| **External Phisher** | Spoofed Emails | Data Exfiltration, Limit Override | Sends emails requesting confidential internal policies, employee data, or direct wire transfers. |
| **Compromised Internal Repository** | Poisoned Documents | Policy Hijacking, Audit Tampering | Leaves poisoned markdown or PDF guidelines claiming tier-1 approval waivers. |
| **Man-in-the-Middle / Prompt Injection** | Tool-Output Manipulation | Approval Bypass, Direct Execution | Fabricates fake approval tokens (e.g. `APP-FAKE-APPROVED`) or claims unverified vendors are approved. |

---

## 3. Attack Taxonomy in the 40-Scenario Benchmark

### 3.1 Category 1: Malicious Emails (8 Scenarios)
- **Vectors:** Email bodies, phishing supplier updates, fake audit requests.
- **Objectives:** Exfiltrating confidential documents (`/internal/procurement_policy_2026.pdf`), redirecting wire transfers to offshore accounts.

### 3.2 Category 2: Malicious Invoices (8 Scenarios)
- **Vectors:** Hidden HTML comments, remittance notes, amount inflation.
- **Objectives:** Replacing approved purchase order bank accounts (`ACC-ACME-8841`) with attacker-controlled accounts (`ACC-ATTACKER-6666`).

### 3.3 Category 3: Poisoned Internal Documents (8 Scenarios)
- **Vectors:** Poisoned vendor directories, fake SOP exceptions, malicious retention memos.
- **Objectives:** Forcing external document forwarding, deleting protected audit logs.

### 3.4 Category 4: Approval & Tool-Output Bypass (8 Scenarios)
- **Vectors:** Fabricated approval IDs, expired token replay, parameter swapping, bypassing `prepare_payment`.
- **Objectives:** Tricking financial execution tools into processing unverified transactions.

### 3.5 Category 5: Benign Controls (8 Scenarios)
- **Vectors:** Standard invoices, approved high-value transactions with authentic approval tokens, status emails.
- **Objective:** Establish utility baseline and measure false-positive rate.

---

## 4. Defense-in-Depth Mitigation Strategy

```
Layer 1: Input Ingestion & Provenance Tagging (Mark untrusted documents as UNTRUSTED)
Layer 2: Server-Side Cryptographic State (Expiring HMAC approvals & single-use nonces)
Layer 3: Pre-Execution Cedar Policy Gateway (Deterministic ALLOW/DENY before tool call)
Layer 4: Continuous Forensic Feedback Loop (Agentic Policy Repair with dual-regression verification)
```
