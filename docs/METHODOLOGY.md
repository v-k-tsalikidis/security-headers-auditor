# Methodology

Security Headers Auditor v0.4 evaluates one HTTP response against the expectations
of an endpoint profile and can compare authorized targets with an explicit
continuous assurance policy and approved baseline. It does not treat every header
as universally applicable.

The normative project specification is
[V0.4 Methodology Specification](V0.4_METHODOLOGY_SPECIFICATION.md). The
[Citation Manifest](CITATION_MANIFEST.md) records the primary standards,
official guidance, and research used by the implementation.

## Assessment Flow

1. Normalize the operator-supplied HTTP or HTTPS target.
2. Request response headers with `HEAD`, using `GET` only after `405` or `501`.
3. Follow same-origin redirects and same-host HTTP-to-HTTPS upgrades; block other
   redirect destinations unless the operator explicitly allows them.
4. Normalize header names without modifying observed values.
5. Apply an explicit profile or conservatively infer `api`, `app`, or `brochure`.
6. Evaluate scored rules using the selected profile's applicability and weights.
7. Analyze reporting readiness and cross-origin isolation outside the score.
8. Attach versioned compliance-supporting evidence with explicit limitations.
9. When policy mode is active, evaluate thresholds and required controls.
10. When an approved baseline is supplied, detect profile, score, and control regressions.
11. When route assurance is supplied, compare exactly one explicit route manifest
    with its separately approved, data-minimized route baseline.
12. Redact URL query strings and fragments unless the operator explicitly retains them.
13. Render human-readable or CI-native output.

## Scoring

Each profile has exactly 100 available points. A rule can receive full, partial,
or zero credit according to the observed value:

```text
score = round(100 * earned_profile_points / available_profile_points)
```

The score describes alignment with the selected response profile. It is not a
vulnerability count, compliance decision, or proof that the application is secure.

| Score | Summary |
| ---: | --- |
| 85-100 | Strong |
| 60-84 | Moderate |
| 35-59 | Needs Review |
| 0-34 | Weak |

## Interpretation

- Auto-detection is evidence-based but cannot prove business purpose.
- Manual `--profile` selection is authoritative and is recorded in the report.
- `not_applicable` means the rule is not assessed for that response profile.
- Contextual observations may still require review even though they do not affect the score.
- Evidence mappings are versioned supporting relationships, not evidence of compliance.
- Reporting readiness does not prove collector delivery or operational response.
- Cross-origin isolation readiness does not prove runtime state or dependency compatibility.
- Policy violations and regressions are separate from the profile score.
- Baselines are approved comparison states, not waivers.
- Route baselines detect drift only within their exact, explicitly declared
  route scope; they do not discover coverage or establish a policy pass.
- CSP, caching, and cross-origin policies require application-specific validation before deployment.

See [Privacy, Accessibility, and Authorization](PRIVACY_ACCESSIBILITY_AUTHORIZATION.md)
for data-handling and authorized-use boundaries.
