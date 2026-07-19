# ADR 0005: Controlled Route-Level Profile Comparison

**Status:** Accepted for v0.6 implementation
**Date:** 2026-07-19

## Context

A single response cannot show whether security-header expectations are applied
consistently across an operator's important routes. Existing continuous
assurance can execute many unrelated targets, but it intentionally treats each
target as an independent policy decision. It does not provide a narrow,
route-level comparison view.

Automatically finding paths would create an unsafe crawler and would blur the
operator's authorization boundary. Comparing unrelated origins, response types,
or raw header values would also produce noisy and unnecessarily sensitive
artifacts.

## Decision

Provide a separate, versioned route-comparison manifest with:

- exactly one HTTP(S) origin;
- 2–25 operator-supplied, origin-relative paths with no query or fragment;
- unique stable IDs and paths, with an explicit response profile for every route;
- the existing read-only audit engine and its default redirect boundary;
- comparison only among successful routes with the same explicit profile;
- a review-only control-variance observation when scored-control states differ;
- a compact summary that excludes raw response-header values.

The mode has no automatic baseline, threshold, compliance result, or
cross-origin-redirect opt-in. Operational errors return the existing error exit
code; a variance alone does not fail the process.

## Consequences

- Operators can expose likely route coverage drift while retaining exact scope
  control and a small artifact surface.
- A profile comparison does not replace continuous assurance policy, baseline
  approval, browser testing, or application-aware route classification.
- This adds no scoring or baseline semantic change, so the current methodology
  version remains valid.
