# CarnotEngine — v7.2 “Reversing Digital Entropy”

**CarnotEngine** converts opaque runtime cryptography into **verifiable understanding** and **future utility**.
We observe TLS handshakes at the endpoint (eBPF/ETW/JFR), enrich with workload context and lineage seeds,
and produce **Cryptographic Context Maps (CCM)** and **receipt-backed attestations** via **Signet**.

> Plain‑English: *We watch your cryptography in real time and turn it into receipts executives can trust
> and auditors can verify — so you can prove you’re safe today and ready for tomorrow.*

## What’s inside

- `docs/` — brand narrative, project context, investor one-pager, today’s execution plan.
- `schema/` — CCM 2.1, Signet receipt and Signed Tree Head (STH) JSON Schemas.
- `introspection-engine/` — eBPF program + Go loader (BPF-side correlation; SNI capture; cgroup; ssl→fd map).
- `signet/` — canonicalization (JCS placeholder), Merkle tree, JWKS/KeyProvider, HTTP message signature scaffold,
  transparency log (SQLite dev), and receipt builder/validator.
- `api/` — FastAPI Signet service (`/ingest`, `/jwks.json`, `/sth`).
- `integrations/` — converter from runtime JSONL → CCM JSON with schema validation.
- `ops/copilot_prompts/` — atomic prompts + acceptance criteria (A00–B1) for Copilot/QodoGen.
- `scripts/` — smoke test, HEL linter, release bundle.
- `.github/workflows/` — CI validation and WORKLOG enforcement.
- `WORKLOG.md` — must be updated in every PR (CI gate).

## Quick start

```bash
# 0) Prepare environment (see ops/copilot_prompts/A00_Onboarding_Environment_Repo.md)
#    Requires: clang, bpftool/libbpf headers, Go 1.22+, Python 3.10+, sqlite3

# 1) Build BPF object + loader
pushd introspection-engine/ebpf-core && make && popd
go build -o introspection-engine/ebpf-core/go-loader/bin/carnot-ebpf-loader ./introspection-engine/ebpf-core/go-loader

# 2) Run smoke (sudo needed for uprobes)
sudo bash scripts/ebpf_smoke_test.sh 10

# 3) Convert to CCM (schema validated)
python3 integrations/runtime/ebpf_to_ccm.py integrations/runtime/runtime.jsonl integrations/runtime/runtime.ccm.json
```

## Known gaps (intentional, with prompts to complete)

- **Negotiated parameters** via BPF CO‑RE (Task **A1**).
- **Strict RFC 8785 JCS & HTTP Message Signatures** with vetted libs (Task **A2**).
- **Key rotation + persistent transparency log hardening** (Task **A3**).
- **Proof carries enrichment & CCM** (Task **A4**).
- **HEL identity/pinning** (Task **A5**).
- **Security tests & coverage ≥80%** (Task **B1**).

See `docs/TODAY_PLAN.md` and `ops/copilot_prompts/` for step‑by‑step execution with acceptance criteria.
