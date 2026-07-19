# Repository Polish Checklist

## Repository Description

Recommended:

```text
Context-aware Python CLI for auditing HTTP security headers with evidence-based profiles and offline reports.
```

Short alternative:

```text
Profile-aware HTTP security headers auditor for apps, APIs, and public sites.
```

## Website

Leave empty until a stable public project or portfolio page exists.

## Topics

Recommended:

```text
python
cybersecurity
web-security
security-headers
http-headers
appsec
owasp
security-audit
security-automation
cli
html-report
accessibility
```

Short set:

```text
python
cybersecurity
web-security
security-headers
appsec
owasp
security-automation
cli
```

## License

Use Apache-2.0. It is established for public security tooling and contains explicit
patent terms.

## Visibility

For portfolio use, make the repository public only when the v0.3 release gate is
complete and the owner is ready to publish it.

## Actions

Expected workflow:

```text
CI
```

Expected matrix:

```text
tests (Python 3.10)
tests (Python 3.11)
tests (Python 3.12)
```

Each job must install the package, compile source and tests, and run the complete
deterministic unittest suite.

## Release

Create the release only after every row in
[RELEASE_GATE_V0.3.md](RELEASE_GATE_V0.3.md) is verified:

```text
Tag: v0.3.0
Target: main
Title: v0.3.0 - Context-aware security header assessment
```

Use [v0.3.0 release notes](releases/v0.3.0.md). Do not publish the generated
ImageGen concept reference; it contains illustrative data and is not part of the
product or evidence set.
