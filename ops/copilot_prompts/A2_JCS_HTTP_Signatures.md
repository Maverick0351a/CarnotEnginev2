# Task A2 — Strict JCS & HTTP Message Signatures

## Goal
Replace placeholder canonicalization and HTTP sig verification with spec-compliant implementations + tests.

## Do
1) Replace `signet/jcs.py` with RFC 8785 exact implementation (byte-for-byte stability).
2) Implement HTTP Message Signatures per current IETF draft using a vetted library or well-tested reference.
3) Add tests:
   - Positive: signature verifies.
   - Negative: header tamper fails; body tamper fails; wrong key ID fails.

## Acceptance Criteria
- `pytest -q` passes all new tests.
- API `/ingest` rejects invalid signatures when verification is enabled (feature flag ok).
