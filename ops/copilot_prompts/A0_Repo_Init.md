# Task A0 — CI validation + WORKLOG gate

## Goal
Ensure CI validates CCM schema and WORKLOG updates.

## Do
1) Open `.github/workflows/tests.yml` and confirm it runs jsonschema validation if CCM exists.
2) Open `.github/workflows/worklog-check.yml` and confirm it fails PRs without WORKLOG changes.

## Acceptance Criteria
- CI green on empty CCM (no file).
- CI fails if WORKLOG not changed on PR (unless label `worklog-bypass` is set).
