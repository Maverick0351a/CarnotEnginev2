# Project Context

**Name**: CarnotEngine  
**Why**: **Reversing Digital Entropy** — convert opaque runtime cryptography into verifiable understanding
and ensure **future utility** of data against threats like the Comprehension Horizon (post‑quantum).

**First Mission**: PQC migration readiness and verification, with **runtime truth** of negotiated TLS parameters,
context enrichment, lineage seeds, and **receipt‑backed** attestations (Signet).

**Core artifacts**:
- **CCM** (Cryptographic Context Map): schema‑validated JSON of runtime observations.
- **Receipts**: Merkle‑linked, signed proofs for batches.
- **STH**: Signed Tree Heads forming a transparency log.
- **Evidence bundles**: CCM + receipts + verification script.

**Non‑goals**: payload inspection, secret collection. Privacy by design (hashable SNI, minimal metadata).
