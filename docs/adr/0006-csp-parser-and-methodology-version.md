# ADR 0006: CSP Parser Semantics And Methodology Version

**Status:** Accepted for v0.6 implementation
**Date:** 2026-07-19

## Context

The former CSP check split one header value on semicolons, lowercased all source
tokens, and overwrote earlier duplicate directives. It could therefore evaluate
the last duplicate instead of the first directive that CSP user agents retain,
and could not distinguish a valid nonce/hash source from a superficially similar
token. It also did not recognize `data:` as an unsafe script source or make its
single-policy scope explicit.

The W3C CSP Level 3 parsing algorithm preserves the first directive with a
given name, treats directive names case-insensitively, and preserves directive
value tokens. Its source-list guidance explicitly warns against `unsafe-inline`
and `data:`. It also describes a comma-delimited CSP policy list whose browser
enforcement is an intersection, not a simple source-list merge.

## Decision

Introduce a bounded shared CSP parser that:

- models a serialized policy list, policy directives, duplicate directives, and
  parser issues without changing or exposing source-token case;
- retains the first duplicate directive and records that later duplicates were
  ignored;
- validates the limited nonce/hash grammar needed to evaluate the existing
  `unsafe-inline` handling;
- detects selected high-risk script expressions, including `data:`;
- reports multiple-policy and parser ambiguity as review signals rather than
  attempting a browser-equivalent composite-policy evaluation;
- is shared by the audit and CSP-reporting-linkage paths.

The CSP score can change for values that the former parser misread or did not
assess. Therefore the tool version becomes `0.6.0`, the methodology version
becomes `0.5.0`, and v0.4 baselines/policies are intentionally incompatible.
Operators must review the new evidence and create a new approved baseline.

## Consequences

- Reports more accurately explain selected static CSP syntax and parser
  behavior while retaining the same read-only request boundary.
- The implementation does not inspect HTML `meta` policies, every response
  header instance as received on the wire, nonce generation/reuse, document
  resource graphs, script execution, browser support, bypass resistance, or
  application compatibility.
- Existing framework mappings remain supporting evidence only. No framework
  mapping, score weight, certification claim, or compliance result is added.
