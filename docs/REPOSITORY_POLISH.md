# Repository Polish Checklist

## Repository Description

Recommended:

```text
Context-aware HTTP security header assurance with profiles, approved baselines, regression detection, and offline reports.
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

For portfolio use, make the repository public only when the v0.4 release gate is
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
deterministic unittest suite. Version 0.4 also runs the local fixture server and
uploads the assurance JSON, SARIF, JUnit, and baseline artifacts.

## Release

Create the release only after every row in
[RELEASE_GATE_V0.4.md](RELEASE_GATE_V0.4.md) is verified:

```text
Tag: v0.4.0
Target: main
Title: v0.4.0 - Continuous security header assurance
```

Use [v0.4.0 release notes](releases/v0.4.0.md). Publish only after the private
repository's GitHub Actions matrix and uploaded artifact set have been verified.
