# Today Plan (v7.2)

**Do tasks in order (A00 → A5 → B1).** Use prompts in `ops/copilot_prompts/`. Each commit must update WORKLOG.

1) A00 — Onboarding, toolchains, repo init (branch protection, CI).
2) A0  — CI sanity: schema validation + WORKLOG gate green.
3) A1  — Negotiated params via BPF CO‑RE (`group_selected`, `cipher_selected`).
4) A2  — Strict RFC 8785 JCS + HTTP Message Signatures; negative tests.
5) A3  — Key rotation + JWKS + persistent transparency log; sign STH.
6) A4  — Proof carries context: cover enrichment + CCM hashes in receipt leaves.
7) A5  — HEL allowlist + SPKI pin; linter passes.
8) B1  — Security tests + coverage ≥80%; tamper cases.

Milestone: produce `artifacts/assessment-*/` bundle with CCM, receipts, STH, and verification output.
