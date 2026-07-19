# Privacy, Accessibility, And Authorization

## Privacy And Data Handling

Security Headers Auditor runs locally and has no analytics, telemetry, accounts,
cloud storage, or third-party scanning API. It sends a read-only HTTP request only
to targets supplied by the operator.

URL query strings and fragments are redacted in every output by default because
they may contain identifiers, reset tokens, session material, search terms, or
other personal or confidential data. The `--include-query` option is an explicit
operator decision and should be used only when the output is controlled.

Response header values are evidence and can themselves contain identifiers,
internal hostnames, software details, policy-report endpoints, or session metadata.
The tool does not persist output unless the operator writes a report. The operator
is responsible for storage, retention, access control, and redaction before sharing.

This data-minimization posture supports privacy-conscious use. It is not a GDPR
compliance assessment, legal opinion, or certification.

Continuous assurance policy files can contain target hosts, paths, organizational
thresholds, and security expectations. Do not store secrets, session identifiers,
reset links, or personal data in policy URLs.

Approved baselines deliberately exclude raw header values and runtime timestamps.
They still reveal target identifiers, selected profiles, scores, and control states
and must be protected as security evidence.

CI systems may upload JSON, SARIF, JUnit, HTML, or Markdown as build artifacts.
Apply repository access controls, artifact retention limits, and redaction before
sharing these outputs outside the authorized team.

Reporting endpoints can receive document URLs, user-agent information, policy
samples, and other operational data. The auditor checks response configuration,
not collector privacy, sanitization, retention, or access control.

## Authorization Boundary

Use the tool only on systems that you:

- own;
- administer; or
- have explicit authorization to assess.

The request model is deliberately narrow:

- one `HEAD` request chain per supplied target;
- one `GET` fallback only after a `405` or `501` response;
- same-origin redirects and same-host HTTP-to-HTTPS upgrades by default;
- blocked cross-origin redirects unless the operator explicitly allows them;
- no crawling, route discovery, authentication, brute force, fuzzing, payload injection,
  exploitation, bypass, or vulnerability confirmation.

The operator supplies the complete target list. The
`--allow-cross-origin-redirects` option must be used only when every possible
redirect destination is inside the authorized scope.

## HTML Report Security

The HTML renderer:

- escapes target, error, evidence, and header values before insertion;
- validates citation schemes before creating links;
- uses `rel="noopener noreferrer"` for new-tab references;
- contains no JavaScript, forms, frames, external fonts, analytics, or remote style assets;
- includes a restrictive document CSP;
- remains a single offline file.

References are external links but are not runtime dependencies. Opening one is an
explicit user action.

## Accessibility

The HTML report is designed for keyboard, screen magnification, reduced-motion,
and screen-reader use:

- semantic headings, tables, lists, definition lists, and native `details` controls;
- a keyboard-visible skip link;
- visible `focus-visible` outlines;
- text labels in addition to status color;
- restrained contrast-aware semantic colors;
- horizontally scrollable tables with keyboard focus;
- responsive reflow at tablet and mobile widths;
- no hover-only information or pointer-only interaction;
- no animation requirement and reduced-motion handling;
- print-specific layout rules.

Automated structure and browser checks reduce regressions but do not replace a
formal WCAG conformance audit with assistive-technology users. WCAG conformance
is therefore not claimed.

## Known Limits

- A response header can be syntactically valid but incompatible with application behavior.
- A single response cannot reveal route sensitivity or complete policy coverage.
- The report does not inspect contrast under user-supplied browser extensions or custom styles.
- Browser QA covers the documented release matrix, not every browser and assistive technology.
- Reporting readiness does not verify collector delivery, availability, or triage.
- Cross-origin isolation readiness does not crawl or execute the document resource graph.
- CI integrations and artifact stores are external processors controlled by the operator.
