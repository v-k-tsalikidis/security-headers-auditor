# Repository Polish Checklist

Use this checklist in GitHub repository settings after pushing the code.

## Repository Description

Recommended description:

```text
Risk-aware Python CLI for auditing HTTP security headers with weighted scoring, readable reports, and public-safe methodology.
```

Alternative shorter description:

```text
Risk-aware HTTP security headers auditor with Markdown/JSON reports.
```

## Website

Leave empty for now.

Add a project/portfolio page later only after a stable public portfolio site exists.

## Topics

Recommended GitHub topics:

```text
python
cybersecurity
web-security
security-headers
http-headers
appsec
owasp
security-audit
blue-team
security-automation
cli
markdown-report
```

If GitHub limits topics, use this shorter set:

```text
python
cybersecurity
web-security
security-headers
http-headers
appsec
owasp
blue-team
security-automation
cli
```

## License

Use Apache-2.0.

Rationale:

- common and credible for security/open-source projects;
- includes explicit patent language;
- aligns naturally with the public security tooling ecosystem;
- avoids ambiguity for anyone reviewing or reusing the project.

## Visibility

For portfolio use, the repository should be public.

If GitHub API or badges return `404`, verify:

- repository visibility is public;
- Actions are enabled;
- the default branch is `main`;
- the pushed commit is visible on GitHub.

## Actions

Expected workflow:

```text
CI
```

Expected jobs:

```text
tests (Python 3.10)
tests (Python 3.11)
tests (Python 3.12)
```

The workflow should be green after the push that introduced `.github/workflows/ci.yml`.

## Release

Create a GitHub release:

```text
Tag: v0.2.0
Target: main
Title: v0.2.0 - Risk-aware header assessment
```

Use the release text from:

```text
docs/releases/v0.2.0.md
```
