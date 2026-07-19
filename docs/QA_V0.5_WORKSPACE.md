# v0.5 Workspace Browser QA Record

**Executed:** 2026-07-19

**Build under test:** `89b0110`

**Browser:** Codex in-app Chromium browser
**Scope:** Deterministic loopback-only QA; no public targets, credentials, or
operator workspace data.

## Test Environment

- `tests/browser_qa_server.py` served the workspace at `127.0.0.1:18766` with
  a temporary SQLite database and a deterministic test-only session token.
- `tests/fixture_server.py` served only repository header fixtures at
  `127.0.0.1:8765`.
- The workspace test process enabled private targets only for these explicitly
  controlled loopback fixtures. Production workspace defaults remain public
  targets only.

## End-to-End Results

| Flow | Evidence | Result |
| --- | --- | --- |
| First launch and workspace creation | Create form rendered; workspace created with an explicit `app` profile and minimum score. | Pass |
| Target lifecycle | Added an `api` profile target, edited the original target, disabled and re-enabled it, then removed the temporary target. | Pass |
| Disabled-target safety | Disabled target displayed `Disabled`; single-target audit and aggregate assurance controls were disabled; latest result was cleared. | Pass |
| Controlled assessment | Local application fixture rendered score, profile decision, findings, and a policy failure without console errors. | Pass |
| Assurance diagnostics | A failing controlled fixture produced explicit policy violations, no false pass, no regressions, and no operational errors. | Pass |
| Evidence boundaries | Evidence view showed ASVS, WSTG, NIST, ATT&CK, and D3FEND relationships with confidence and explicit limitations. | Pass |
| Hostile response handling | Hostile fixture content remained visible as text; the workspace main content contained zero script elements and zero injected image elements. | Pass |
| Invalid import recovery | Unsupported schema `999.0` showed an actionable alert and did not replace the open workspace or start an audit. | Pass |

## Accessibility And Responsive Review

- At desktop width (1280 CSS px), the workspace rendered meaningful content,
  landmarks, tables, buttons, dialogs, progress semantics, and no console
  warnings or errors.
- At 390 x 844 CSS px, the assurance view reflowed to the mobile navigation and
  two-column summary without horizontal overflow.
- Keyboard-focused `Report format` rendered a solid `3px` focus outline with a
  `2px` offset. The page provides a skip link, named navigation, labelled
  controls, alert semantics, and modal dialog semantics.
- Primary text and status-color tokens meet the normal-text 4.5:1 contrast
  threshold against white: text 15.65:1, muted 5.08:1, teal 6.83:1, green
  5.85:1, ochre 5.10:1, and rose 6.34:1.
- `prefers-reduced-motion: reduce` reduces animation and transition duration
  and disables smooth scrolling. The 390px review provides the effective
  layout-width check used for high-zoom reflow.

## Limits

This is deterministic functional QA in one Chromium-based browser, not a
substitute for assistive-technology testing or a cross-browser certification.
The release uses this record together with the static accessibility contracts,
frontend tests, and workspace integration suite.

## Controlled Documentation Screenshots

The target inventory, assessment, and assurance states were captured again on
2026-07-19 using the same local fixture server and a temporary workspace named
`v0.5 Controlled QA`. The saved images contain only `127.0.0.1` fixtures and
show an assessment and assurance **failure** rather than implying a pass:

- [Target inventory](images/v0.5-workspace-targets.jpg)
- [Assessment](images/v0.5-workspace-assessment.jpg)
- [Assurance diagnostics](images/v0.5-workspace-assurance.jpg)
