# Release Gate: v0.3.0

No release is considered complete until every applicable gate has recorded evidence.

| Gate | Required evidence | Status |
| --- | --- | --- |
| Methodology | Taxonomy, weights, rationale, citations, non-goals documented | Verified |
| Profile engine | Auto-detection, confidence, evidence, and manual override tested | Verified |
| Findings | Profile applicability and stable scores covered by local fixtures | Verified |
| Input safety | Scheme validation, credential rejection, URL redaction, redirect boundary, and fallback policy tested | Verified |
| HTML safety | Escaping, safe links, no script, restrictive CSP, no remote runtime assets | Verified |
| Regression suite | All unit tests pass without remote sites | Verified |
| Package build | Offline wheel builds and installs in an isolated virtual environment | Verified |
| Python compatibility | GitHub Actions matrix passes on Python 3.10, 3.11, and 3.12 | Pending |
| Desktop browser QA | Layout, interaction, overflow, and console inspection | Verified |
| Mobile browser QA | Reflow, text fit, controls, and horizontal overflow inspection | Verified |
| Accessibility review | Semantic structure, native controls, focus styling, non-color status, contrast, reduced motion | Verified within documented limits |
| Documentation | README, privacy/authorization, methodology, release notes aligned | Verified |
| Repository state | Intended diff reviewed and release commit identified | Pending |

## Local Automated Evidence

Command:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Current local result:

```text
Ran 32 tests
OK
```

## Browser Evidence

- Desktop: in-app Chromium browser, `1440 x 1000`; no document-level horizontal
  overflow, no console warnings/errors, no external runtime assets, and finding
  disclosure interaction verified.
- Mobile: in-app Chromium browser, `390 x 844`; no document-level horizontal
  overflow, responsive content reflow verified, and wide data tables contained in
  keyboard-focusable horizontal scroll regions.
- Structure: one H1, semantic H2/H3/H4 hierarchy, skip link, labelled progress,
  native `details`/`summary`, scoped tables, text status labels, and reduced-motion CSS.
- Contrast: body, muted, link, pass, warning, missing, and info text/background
  pairs all measured at `5.19:1` or higher.
- Console: no warnings or errors during desktop/mobile loading and disclosure use.

## Package Evidence

```text
security_headers_auditor-0.3.0-py3-none-any.whl
Successfully installed security-headers-auditor-0.3.0
```

The GitHub Actions Python matrix and final repository state remain required before
the release is labelled complete.
