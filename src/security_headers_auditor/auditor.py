"""Core HTTP security header checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class HeaderRule:
    key: str
    name: str
    category: str
    weight: int
    purpose: str
    recommendation: str
    reference: str


BASELINE_RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        key="strict-transport-security",
        name="Strict-Transport-Security",
        category="baseline",
        weight=20,
        purpose="Reduces downgrade and protocol-stripping exposure after first HTTPS use.",
        recommendation=(
            "Serve over HTTPS and use max-age of at least 31536000 seconds; consider "
            "63072000 and includeSubDomains after domain readiness review."
        ),
        reference="OWASP Secure Headers Project / MDN HSTS",
    ),
    HeaderRule(
        key="content-security-policy",
        name="Content-Security-Policy",
        category="baseline",
        weight=20,
        purpose="Limits content injection and cross-site scripting blast radius.",
        recommendation=(
            "Define a site-specific CSP. Prefer default-src/script-src controls, "
            "object-src 'none', base-uri 'self' or 'none', and frame-ancestors where possible."
        ),
        reference="web.dev CSP guidance / OWASP Secure Headers Project",
    ),
    HeaderRule(
        key="x-content-type-options",
        name="X-Content-Type-Options",
        category="baseline",
        weight=10,
        purpose="Prevents MIME sniffing when the declared content type should be trusted.",
        recommendation="Use X-Content-Type-Options: nosniff.",
        reference="MDN HTTP headers",
    ),
    HeaderRule(
        key="x-frame-options",
        name="X-Frame-Options",
        category="baseline",
        weight=10,
        purpose="Provides a legacy clickjacking control for frame embedding.",
        recommendation=(
            "Use DENY or SAMEORIGIN, or use CSP frame-ancestors with awareness that "
            "older clients may still rely on X-Frame-Options."
        ),
        reference="MDN X-Frame-Options / OWASP Secure Headers Project",
    ),
    HeaderRule(
        key="referrer-policy",
        name="Referrer-Policy",
        category="baseline",
        weight=10,
        purpose="Limits leakage of URLs and query data through the Referer header.",
        recommendation=(
            "Prefer no-referrer, same-origin, strict-origin, or "
            "strict-origin-when-cross-origin depending on application needs."
        ),
        reference="MDN Referrer-Policy",
    ),
    HeaderRule(
        key="permissions-policy",
        name="Permissions-Policy",
        category="baseline",
        weight=10,
        purpose="Restricts browser features that pages and embedded frames can use.",
        recommendation="Disable unused powerful browser features explicitly.",
        reference="web.dev security headers / MDN HTTP headers",
    ),
    HeaderRule(
        key="cross-origin-opener-policy",
        name="Cross-Origin-Opener-Policy",
        category="baseline",
        weight=10,
        purpose="Reduces cross-origin window interaction risk.",
        recommendation="Use same-origin unless the application requires a looser opener policy.",
        reference="web.dev security headers / MDN HTTP headers",
    ),
    HeaderRule(
        key="cross-origin-resource-policy",
        name="Cross-Origin-Resource-Policy",
        category="baseline",
        weight=10,
        purpose="Controls whether other origins can read the response as a resource.",
        recommendation="Use same-origin or same-site for sensitive resources where compatible.",
        reference="web.dev security headers / MDN HTTP headers",
    ),
)


CONTEXTUAL_RULES: tuple[HeaderRule, ...] = (
    HeaderRule(
        key="cross-origin-embedder-policy",
        name="Cross-Origin-Embedder-Policy",
        category="contextual",
        weight=0,
        purpose="Supports cross-origin isolation for applications that need advanced browser capabilities.",
        recommendation="Evaluate require-corp only when the application is ready for cross-origin isolation.",
        reference="web.dev security headers / MDN HTTP headers",
    ),
    HeaderRule(
        key="clear-site-data",
        name="Clear-Site-Data",
        category="contextual",
        weight=0,
        purpose="Can clear browser-side state on sensitive flows such as logout.",
        recommendation="Consider on logout or account-reset endpoints, not necessarily every response.",
        reference="OWASP Secure Headers Project",
    ),
    HeaderRule(
        key="cache-control",
        name="Cache-Control",
        category="contextual",
        weight=0,
        purpose="Can prevent sensitive content from remaining in local browser caches.",
        recommendation="Use no-store for authenticated or sensitive responses.",
        reference="OWASP Secure Headers Project",
    ),
    HeaderRule(
        key="x-permitted-cross-domain-policies",
        name="X-Permitted-Cross-Domain-Policies",
        category="contextual",
        weight=0,
        purpose="Restricts legacy cross-domain policy files.",
        recommendation="Use none unless legacy client requirements justify otherwise.",
        reference="OWASP Secure Headers Project",
    ),
    HeaderRule(
        key="x-dns-prefetch-control",
        name="X-DNS-Prefetch-Control",
        category="contextual",
        weight=0,
        purpose="Controls DNS prefetching for privacy-sensitive pages.",
        recommendation="Consider off on pages with sensitive or private content.",
        reference="OWASP Secure Headers Project",
    ),
)


DISCLOSURE_HEADERS: dict[str, tuple[str, str]] = {
    "server": ("Server", "May disclose web server or platform details."),
    "x-powered-by": ("X-Powered-By", "May disclose framework, language, or hosting details."),
    "x-aspnet-version": ("X-AspNet-Version", "May disclose ASP.NET runtime details."),
    "x-aspnetmvc-version": ("X-AspNetMvc-Version", "May disclose ASP.NET MVC framework details."),
    "x-generator": ("X-Generator", "May disclose CMS or generator details."),
    "x-cms": ("X-CMS", "May disclose CMS details."),
    "x-php-version": ("X-Php-Version", "May disclose PHP version details."),
}


@dataclass(frozen=True)
class HeaderFinding:
    name: str
    status: str
    severity: str
    category: str
    value: str | None
    note: str
    recommendation: str
    reference: str
    points: float = 0.0
    max_points: int = 0


@dataclass(frozen=True)
class AuditResult:
    target: str
    final_url: str | None
    status_code: int | None
    score: int
    summary: str
    findings: list[HeaderFinding]
    error: str | None = None


def normalize_target(target: str) -> str:
    """Normalize a target into an HTTP(S) URL."""
    target = target.strip()
    if not target:
        raise ValueError("Target cannot be empty.")

    parsed = urlparse(target)
    if not parsed.scheme:
        target = f"https://{target}"
        parsed = urlparse(target)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")

    if not parsed.netloc:
        raise ValueError(f"Invalid target URL: {target}")

    return target


def fetch_headers(target: str, timeout: float = 8.0) -> tuple[str, int, Mapping[str, str]]:
    """Fetch response headers using HEAD first, then GET as a compatibility fallback."""
    normalized = normalize_target(target)
    headers = {
        "User-Agent": "security-headers-auditor/0.1 (+https://github.com/v-k-tsalikidis/security-headers-auditor)"
    }

    request = Request(normalized, headers=headers, method="HEAD")
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.geturl(), response.status, dict(response.headers.items())
    except (HTTPError, URLError, ValueError):
        request = Request(normalized, headers=headers, method="GET")
        with urlopen(request, timeout=timeout) as response:
            return response.geturl(), response.status, dict(response.headers.items())


def audit_headers(target: str, timeout: float = 8.0) -> AuditResult:
    """Audit a target and return structured findings."""
    try:
        final_url, status_code, raw_headers = fetch_headers(target, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - CLI reports network/parser failures cleanly.
        return AuditResult(
            target=target,
            final_url=None,
            status_code=None,
            score=0,
            summary="Error",
            findings=[],
            error=str(exc),
        )

    normalized_headers = _normalize_headers(raw_headers)
    findings: list[HeaderFinding] = []

    for rule in BASELINE_RULES:
        findings.append(_evaluate_baseline_rule(rule, normalized_headers, final_url))

    for rule in CONTEXTUAL_RULES:
        findings.append(_evaluate_contextual_rule(rule, normalized_headers))

    findings.extend(_evaluate_disclosure_headers(normalized_headers))

    score = _weighted_score(findings)
    summary = _score_summary(score)

    return AuditResult(
        target=target,
        final_url=final_url,
        status_code=status_code,
        score=score,
        summary=summary,
        findings=findings,
    )


def _normalize_headers(raw_headers: Mapping[str, str]) -> dict[str, str]:
    return {key.lower(): value.strip() for key, value in raw_headers.items()}


def _evaluate_baseline_rule(
    rule: HeaderRule,
    headers: Mapping[str, str],
    final_url: str,
) -> HeaderFinding:
    value = headers.get(rule.key)
    if not value:
        return _finding(rule, "missing", "high", None, rule.purpose, 0.0)

    evaluator = {
        "strict-transport-security": _evaluate_hsts,
        "content-security-policy": _evaluate_csp,
        "x-content-type-options": _evaluate_x_content_type_options,
        "x-frame-options": _evaluate_x_frame_options,
        "referrer-policy": _evaluate_referrer_policy,
        "permissions-policy": _evaluate_permissions_policy,
        "cross-origin-opener-policy": _evaluate_coop,
        "cross-origin-resource-policy": _evaluate_corp,
    }.get(rule.key)

    if evaluator is None:
        return _finding(rule, "pass", "info", value, rule.purpose, float(rule.weight))

    return evaluator(rule, value, headers, final_url)


def _evaluate_contextual_rule(rule: HeaderRule, headers: Mapping[str, str]) -> HeaderFinding:
    value = headers.get(rule.key)
    if value:
        return _finding(rule, "info", "info", value, rule.purpose, 0.0)
    return _finding(
        rule,
        "info",
        "info",
        None,
        f"{rule.purpose} This is context-dependent and is not included in the score.",
        0.0,
    )


def _evaluate_disclosure_headers(headers: Mapping[str, str]) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    for header_key, (header_name, note) in DISCLOSURE_HEADERS.items():
        value = headers.get(header_key)
        if not value:
            continue
        findings.append(
            HeaderFinding(
                name=header_name,
                status="info",
                severity="low",
                category="disclosure",
                value=value,
                note=note,
                recommendation="Remove or normalize this header if it exposes unnecessary stack details.",
                reference="OWASP Secure Headers Project information-disclosure guidance",
            )
        )
    return findings


def _evaluate_hsts(
    rule: HeaderRule,
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> HeaderFinding:
    del headers
    parsed_url = urlparse(final_url)
    if parsed_url.scheme != "https":
        return _finding(
            rule,
            "warning",
            "high",
            value,
            "HSTS is only effective over HTTPS; the final URL is not HTTPS.",
            rule.weight * 0.5,
        )

    max_age = _parse_max_age(value)
    if max_age is None:
        return _finding(
            rule,
            "warning",
            "high",
            value,
            "HSTS is present but max-age could not be parsed.",
            rule.weight * 0.5,
        )
    if max_age < 31_536_000:
        return _finding(
            rule,
            "warning",
            "medium",
            value,
            "HSTS is present but max-age is below the common one-year baseline.",
            rule.weight * 0.5,
        )
    if "includesubdomains" not in value.lower():
        return _finding(
            rule,
            "warning",
            "low",
            value,
            "HSTS max-age is strong, but includeSubDomains is absent.",
            rule.weight * 0.75,
        )
    return _finding(rule, "pass", "info", value, rule.purpose, float(rule.weight))


def _evaluate_csp(
    rule: HeaderRule,
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> HeaderFinding:
    del headers, final_url
    lower_value = value.lower()
    weak_signals = ("'unsafe-inline'", "'unsafe-eval'", " default-src *", " script-src *")
    if any(signal in lower_value for signal in weak_signals):
        return _finding(
            rule,
            "warning",
            "high",
            value,
            "CSP is present but contains broad or unsafe directives that may weaken protection.",
            rule.weight * 0.5,
        )

    missing_hardening = [
        directive
        for directive in ("object-src", "base-uri")
        if directive not in lower_value
    ]
    if missing_hardening:
        return _finding(
            rule,
            "warning",
            "medium",
            value,
            "CSP is present but could be hardened with: " + ", ".join(missing_hardening),
            rule.weight * 0.75,
        )

    return _finding(rule, "pass", "info", value, rule.purpose, float(rule.weight))


def _evaluate_x_content_type_options(
    rule: HeaderRule,
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> HeaderFinding:
    del headers, final_url
    if value.lower() == "nosniff":
        return _finding(rule, "pass", "info", value, rule.purpose, float(rule.weight))
    return _finding(
        rule,
        "warning",
        "medium",
        value,
        "Header is present but does not use the expected nosniff value.",
        rule.weight * 0.5,
    )


def _evaluate_x_frame_options(
    rule: HeaderRule,
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> HeaderFinding:
    del final_url
    normalized = value.lower()
    if normalized in {"deny", "sameorigin"}:
        return _finding(rule, "pass", "info", value, rule.purpose, float(rule.weight))
    if "frame-ancestors" in headers.get("content-security-policy", "").lower():
        return _finding(
            rule,
            "warning",
            "low",
            value,
            "X-Frame-Options value is unusual, but CSP frame-ancestors is present.",
            rule.weight * 0.5,
        )
    return _finding(
        rule,
        "warning",
        "medium",
        value,
        "Header is present but does not use DENY or SAMEORIGIN.",
        rule.weight * 0.5,
    )


def _evaluate_referrer_policy(
    rule: HeaderRule,
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> HeaderFinding:
    del headers, final_url
    strict_values = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    normalized = value.lower()
    if normalized in strict_values:
        return _finding(rule, "pass", "info", value, rule.purpose, float(rule.weight))
    if normalized == "unsafe-url":
        return _finding(
            rule,
            "warning",
            "high",
            value,
            "unsafe-url can leak full HTTPS URLs to less trustworthy contexts.",
            rule.weight * 0.25,
        )
    return _finding(
        rule,
        "warning",
        "medium",
        value,
        "Policy is present but should be reviewed against privacy requirements.",
        rule.weight * 0.5,
    )


def _evaluate_permissions_policy(
    rule: HeaderRule,
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> HeaderFinding:
    del headers, final_url
    if "=()" in value or "()" in value:
        return _finding(rule, "pass", "info", value, rule.purpose, float(rule.weight))
    return _finding(
        rule,
        "warning",
        "medium",
        value,
        "Header is present but does not clearly disable unused browser features.",
        rule.weight * 0.5,
    )


def _evaluate_coop(
    rule: HeaderRule,
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> HeaderFinding:
    del headers, final_url
    normalized = value.lower()
    if normalized in {"same-origin", "same-origin-allow-popups"}:
        return _finding(rule, "pass", "info", value, rule.purpose, float(rule.weight))
    return _finding(
        rule,
        "warning",
        "medium",
        value,
        "COOP is present but does not use a strong opener isolation value.",
        rule.weight * 0.5,
    )


def _evaluate_corp(
    rule: HeaderRule,
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> HeaderFinding:
    del headers, final_url
    normalized = value.lower()
    if normalized in {"same-origin", "same-site", "cross-origin"}:
        return _finding(rule, "pass", "info", value, rule.purpose, float(rule.weight))
    return _finding(
        rule,
        "warning",
        "medium",
        value,
        "CORP is present but does not use a recognized policy value.",
        rule.weight * 0.5,
    )


def _finding(
    rule: HeaderRule,
    status: str,
    severity: str,
    value: str | None,
    note: str,
    points: float,
) -> HeaderFinding:
    return HeaderFinding(
        name=rule.name,
        status=status,
        severity=severity,
        category=rule.category,
        value=value,
        note=note,
        recommendation=rule.recommendation,
        reference=rule.reference,
        points=points,
        max_points=rule.weight,
    )


def _parse_max_age(value: str) -> int | None:
    for directive in value.split(";"):
        name, _, raw_value = directive.strip().partition("=")
        if name.lower() != "max-age":
            continue
        try:
            return int(raw_value)
        except ValueError:
            return None
    return None


def _weighted_score(findings: list[HeaderFinding]) -> int:
    baseline = [finding for finding in findings if finding.category == "baseline"]
    max_points = sum(finding.max_points for finding in baseline)
    if max_points == 0:
        return 0
    points = sum(finding.points for finding in baseline)
    return round(100 * points / max_points)


def _canonical_header_name(header_name: str) -> str:
    return "-".join(part.upper() if part in {"x"} else part.capitalize() for part in header_name.split("-"))


def _score_summary(score: int) -> str:
    if score >= 85:
        return "Strong"
    if score >= 60:
        return "Moderate"
    if score >= 35:
        return "Needs Review"
    return "Weak"
