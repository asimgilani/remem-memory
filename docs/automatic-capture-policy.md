# Automatic capture policy v1

**Date:** 2026-09-07
**Status:** Complete
**Purpose:** Language-neutral fixture contract for automatic Remem capture, including the later OpenClaw port.

The executable policy lives in `plugins/remem-memory/scripts/memory_policy.py` as
`evaluate_automatic_capture`. The versioned cases are
`tests/fixtures/automatic-capture-policy-v1.json`. Plugin tests in
`tests/test_automatic_capture_policy.py` are the current conformance suite.

## What it covers

Automatic durable conversation capture, session checkpoints and rollups, the
background queue, prepared capture records, and ingest of those records,
including delayed retry of a legacy prepared or queued item.

It does not cover explicit user-requested raw storage, manual
checkpoint/rollup/recall helpers, or explicit MCP writes. Those stay a
separate policy. Manual storage is never reclassified as automatic.

## Detector limits

This is best-effort pattern, credential-field, entropy, and off-record
detection. It is not complete protection. Known false positives are in the
fixture, including opaque local temp-path entropy unless the caller marks that
exact path as a trusted fragment.

Rejected text must not appear in queue files, new prepared rows, receipts,
state files, or transport bodies. Safe outcomes use fixed reasons such as
`policy`, `secret`, and `off-record`, plus an integer match count. They must
not echo the rejected payload.

## Legacy rejection

If a pending prepared row already contains a fixture secret or off-record
span, retry must not ingest it. The live queue event is discarded. Receipts
keep only non-content cursor fields. The append-only prepared log is not
rewritten, so an operator may still see the historical row in that file.

Allowed captures keep at-least-once retry until delivery or exhaustion.

## OpenClaw port

Implement the same `automatic-capture-policy-v1` fixture against OpenClaw
capture persistence and ingest. Do not edit installed plugin artifacts. A
client passes when every fixture case matches `expect`/`reason`, reject
needles never enter that client's automatic queue/prepared/receipt/state or
transport, and allowed cases still retry after a transient failure.
