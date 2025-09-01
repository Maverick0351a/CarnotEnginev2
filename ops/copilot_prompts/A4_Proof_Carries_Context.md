# Task A4 — Proof Covers Enrichment & CCM

## Goal
Include hashes of enrichment and CCM observation in the receipt leaf so the whole intelligence chain is covered.

## Do
1) Extend loader to compute `raw_event_hash` (from ringbuf event), `enrichment_hash` (post-enrichment), and after conversion `ccm_obs_hash`.
2) Update `signet/receipts.py` to accept these three and build the leaf accordingly.
3) Update `/ingest` to accept these fields

## Acceptance Criteria
- Receipt contains `context.raw_event_hash`, `enrichment_hash`, and `ccm_obs_hash` (per schema).
- `tools/verify_receipt.py` recomputes leaf and matches proof.
