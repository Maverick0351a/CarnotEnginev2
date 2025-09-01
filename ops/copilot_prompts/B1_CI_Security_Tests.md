# Task B1 — Security Tests & Coverage

## Goal
Add tests to reach ≥80% coverage for signet + api; include tamper tests.

## Do
1) Add pytest with coverage to CI workflow.
2) Negative tests:
   - Modify any part of a stored leaf payload → verification fails.
   - Modify STH → signature mismatch.
3) Simple benchmark: throughput of `/ingest` with batch size 100.

## Acceptance Criteria
- Coverage ≥80% for `signet/*` and `api/main.py`.
- Negative tests fail as expected; CI green.
