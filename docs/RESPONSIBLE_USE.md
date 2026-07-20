# Responsible Use

Security Headers Auditor is intended for defensive review of systems the
operator owns, administers, or is expressly authorized to assess. Its purpose
is to identify potential HTTP response-header configuration weaknesses and
support their remediation and change review.

## Deliberately Low-Impact Operation

- The operator supplies each target; the tool does not discover or crawl
  routes.
- An audit uses one `HEAD` request chain per supplied target. It makes one
  `GET` compatibility fallback only after a `405` or `501` response.
- Cross-origin redirects are blocked by default. Private, loopback, link-local,
  and reserved targets are blocked by default in the local workspace.
- The tool does not authenticate, brute-force, fuzz, inject payloads, exploit,
  bypass controls, or confirm a vulnerability.

These safeguards reduce operational impact. They do not establish permission,
prove a target is safe to assess, or replace an operator’s responsibility to
define and respect the authorized scope.

## Public Source And Intended Use

The repository is public so its implementation, assumptions, limitations, and
evidence model can be inspected, learned from, and improved. Apache-2.0 governs
the software license. This responsible-use statement is an engineering and
community expectation for the project; it is not presented as legal advice or
as a substitute for an organization’s authorization process.

For implementation details, see
[Privacy, Accessibility, and Authorization](PRIVACY_ACCESSIBILITY_AUTHORIZATION.md)
and [the project disclaimer](../DISCLAIMER.md).
