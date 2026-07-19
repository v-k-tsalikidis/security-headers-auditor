"""Context-aware HTTP security header assessment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
from urllib.error import HTTPError
from urllib.parse import ParseResult, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import __version__
from .assurance_controls import (
    ControlObservation,
    analyze_cross_origin_isolation,
    analyze_reporting_readiness,
)
from .catalog import DISCLOSURE_HEADERS, RULES, HeaderRule
from .compliance import EvidenceMapping, mappings_for_control
from .profiles import (
    Applicability,
    ProfileDecision,
    ProfileName,
    RulePolicy,
    profile_definition,
    resolve_profile,
)


@dataclass(frozen=True)
class HeaderFinding:
    key: str
    name: str
    status: str
    severity: str
    category: str
    applicability: str
    value: str | None
    note: str
    recommendation: str
    scoring_rationale: str
    citation_keys: tuple[str, ...]
    standards: tuple[str, ...]
    evidence_mappings: tuple[EvidenceMapping, ...] = ()
    points: float = 0.0
    max_points: int = 0


@dataclass(frozen=True)
class AuditResult:
    target: str
    final_url: str | None
    status_code: int | None
    requested_profile: str
    selected_profile: str | None
    profile_label: str | None
    profile_confidence: str | None
    profile_evidence: tuple[str, ...]
    score: int
    summary: str
    findings: list[HeaderFinding]
    error: str | None = None


@dataclass(frozen=True)
class _Evaluation:
    status: str
    severity: str
    note: str
    credit_ratio: float


class RedirectBoundaryError(RuntimeError):
    """Raised when a redirect would leave the operator-supplied origin."""


class _ScopeRedirectHandler(HTTPRedirectHandler):
    def __init__(self, initial_url: str, allow_cross_origin_redirects: bool):
        super().__init__()
        self.initial_url = initial_url
        self.allow_cross_origin_redirects = allow_cross_origin_redirects

    def redirect_request(
        self,
        req: Request,
        fp: object,
        code: int,
        msg: str,
        headers: Mapping[str, str],
        newurl: str,
    ) -> Request | None:
        if not self.allow_cross_origin_redirects and not _redirect_is_allowed(
            self.initial_url,
            newurl,
        ):
            raise RedirectBoundaryError(
                "Cross-origin redirect blocked: "
                f"{_origin_label(self.initial_url)} -> {_origin_label(newurl)}. "
                "Use --allow-cross-origin-redirects only when the destination is authorized."
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


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
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not supported.")

    return target


def redact_url(url: str, include_query: bool = False) -> str:
    """Remove URL query and fragment data unless the user explicitly opts in."""
    parsed = urlparse(url)
    if include_query:
        return url
    query = "<redacted>" if parsed.query else ""
    fragment = "<redacted>" if parsed.fragment else ""
    return urlunparse(parsed._replace(query=query, fragment=fragment))


def fetch_headers(
    target: str,
    timeout: float = 8.0,
    allow_cross_origin_redirects: bool = False,
) -> tuple[str, int, Mapping[str, str]]:
    """Fetch one response chain, with a narrowly scoped GET compatibility fallback."""
    normalized = normalize_target(target)
    headers = {
        "User-Agent": (
            f"security-headers-auditor/{__version__} "
            "(+https://github.com/v-k-tsalikidis/security-headers-auditor)"
        )
    }
    opener = build_opener(
        _ScopeRedirectHandler(normalized, allow_cross_origin_redirects)
    )

    request = Request(normalized, headers=headers, method="HEAD")
    try:
        with opener.open(request, timeout=timeout) as response:
            return _response_tuple(response)
    except HTTPError as exc:
        if exc.code not in {405, 501}:
            try:
                return _response_tuple(exc)
            finally:
                exc.close()

    request = Request(normalized, headers=headers, method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            return _response_tuple(response)
    except HTTPError as exc:
        try:
            return _response_tuple(exc)
        finally:
            exc.close()


def audit_headers(
    target: str,
    timeout: float = 8.0,
    profile: str = "auto",
    include_query: bool = False,
    allow_cross_origin_redirects: bool = False,
    reporting_expectation: str = "observe",
    cross_origin_isolation: str = "observe",
) -> AuditResult:
    """Audit one response and return profile-aware structured findings."""
    try:
        final_url, status_code, raw_headers = fetch_headers(
            target,
            timeout=timeout,
            allow_cross_origin_redirects=allow_cross_origin_redirects,
        )
        normalized_headers = _normalize_headers(raw_headers)
        decision = resolve_profile(profile, normalized_headers)
    except Exception as exc:  # noqa: BLE001 - the CLI reports input/network failures cleanly.
        return AuditResult(
            target=redact_url(target, include_query=include_query),
            final_url=None,
            status_code=None,
            requested_profile=profile,
            selected_profile=None,
            profile_label=None,
            profile_confidence=None,
            profile_evidence=(),
            score=0,
            summary="Error",
            findings=[],
            error=_safe_error_message(exc, target, include_query),
        )

    definition = profile_definition(decision.selected)
    findings = [
        _evaluate_rule(
            rule=rule,
            policy=definition.policies[rule.key],
            headers=normalized_headers,
            final_url=final_url,
        )
        for rule in RULES
    ]
    findings.extend(
        _observation_finding(observation)
        for observation in analyze_reporting_readiness(
            normalized_headers,
            final_url,
            reporting_expectation,
        )
    )
    findings.append(
        _observation_finding(
            analyze_cross_origin_isolation(
                normalized_headers,
                cross_origin_isolation,
            )
        )
    )
    findings.extend(_evaluate_disclosure_headers(normalized_headers))

    score = _weighted_score(findings)
    return AuditResult(
        target=redact_url(target, include_query=include_query),
        final_url=redact_url(final_url, include_query=include_query),
        status_code=status_code,
        requested_profile=decision.requested,
        selected_profile=decision.selected.value,
        profile_label=definition.label,
        profile_confidence=decision.confidence,
        profile_evidence=decision.evidence,
        score=score,
        summary=_score_summary(score),
        findings=findings,
    )


def _normalize_headers(raw_headers: Mapping[str, str]) -> dict[str, str]:
    return {key.lower(): value.strip() for key, value in raw_headers.items()}


def _response_tuple(response: object) -> tuple[str, int, Mapping[str, str]]:
    status = getattr(response, "status", None)
    if status is None:
        status = response.code
    return (
        response.geturl(),
        int(status),
        dict(response.headers.items()),
    )


def _redirect_is_allowed(initial_url: str, destination_url: str) -> bool:
    initial = urlparse(initial_url)
    destination = urlparse(destination_url)
    if _origin(initial) == _origin(destination):
        return True
    return (
        initial.scheme == "http"
        and destination.scheme == "https"
        and initial.hostname == destination.hostname
        and _effective_port(initial) == 80
        and _effective_port(destination) == 443
    )


def _origin(parsed_url: ParseResult) -> tuple[str, str | None, int | None]:
    return (
        parsed_url.scheme.lower(),
        parsed_url.hostname.lower() if parsed_url.hostname else None,
        _effective_port(parsed_url),
    )


def _effective_port(parsed_url: ParseResult) -> int | None:
    if parsed_url.port is not None:
        return parsed_url.port
    return {"http": 80, "https": 443}.get(parsed_url.scheme.lower())


def _origin_label(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _safe_error_message(
    error: Exception,
    target: str,
    include_query: bool,
) -> str:
    message = str(error)
    if include_query:
        return message
    return message.replace(target, redact_url(target))


def _evaluate_rule(
    rule: HeaderRule,
    policy: RulePolicy,
    headers: Mapping[str, str],
    final_url: str,
) -> HeaderFinding:
    value = headers.get(rule.key)
    category = "scored" if policy.weight else "contextual"

    if policy.applicability == Applicability.NOT_APPLICABLE:
        observed = f" Header observed with value: {value}." if value else ""
        return _finding(
            rule=rule,
            policy=policy,
            status="not_applicable",
            severity="info",
            category=category,
            value=value,
            note=f"Not assessed for this profile. {policy.rationale}{observed}".strip(),
            credit_ratio=0.0,
        )

    if not value:
        if rule.key == "x-frame-options" and _has_frame_ancestors(headers):
            return _finding(
                rule=rule,
                policy=policy,
                status="pass",
                severity="info",
                category=category,
                value=None,
                note=(
                    "The legacy X-Frame-Options header is absent, but an explicit CSP "
                    "frame-ancestors directive provides the modern framing control."
                ),
                credit_ratio=1.0,
            )
        if policy.weight:
            severity = "high" if policy.applicability == Applicability.REQUIRED else "medium"
            return _finding(
                rule=rule,
                policy=policy,
                status="missing",
                severity=severity,
                category=category,
                value=None,
                note=rule.purpose,
                credit_ratio=0.0,
            )
        return _finding(
            rule=rule,
            policy=policy,
            status="info",
            severity="info",
            category=category,
            value=None,
            note=f"{rule.purpose} {policy.rationale}",
            credit_ratio=0.0,
        )

    evaluator = _EVALUATORS.get(rule.key)
    if evaluator is None:
        evaluation = _Evaluation("pass", "info", rule.purpose, 1.0)
    else:
        evaluation = evaluator(value, headers, final_url)

    if not policy.weight and evaluation.status in {"pass", "warning"}:
        evaluation = _Evaluation(
            status="info" if evaluation.status == "pass" else "review",
            severity="info" if evaluation.status == "pass" else evaluation.severity,
            note=evaluation.note,
            credit_ratio=0.0,
        )

    return _finding(
        rule=rule,
        policy=policy,
        status=evaluation.status,
        severity=evaluation.severity,
        category=category,
        value=value,
        note=evaluation.note,
        credit_ratio=evaluation.credit_ratio,
    )


def _evaluate_disclosure_headers(headers: Mapping[str, str]) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    for header_key, (header_name, note) in DISCLOSURE_HEADERS.items():
        value = headers.get(header_key)
        if not value:
            continue
        findings.append(
            HeaderFinding(
                key=header_key,
                name=header_name,
                status="observed",
                severity="low",
                category="disclosure",
                applicability="informational",
                value=value,
                note=note,
                recommendation="Remove or normalize the header if it exposes unnecessary stack details.",
                scoring_rationale="Disclosure observations never affect the profile score.",
                citation_keys=("owasp-secure-headers",),
                standards=(),
            )
        )
    return findings


def _observation_finding(observation: ControlObservation) -> HeaderFinding:
    mappings = mappings_for_control(observation.key)
    return HeaderFinding(
        key=observation.key,
        name=observation.name,
        status=observation.status,
        severity=observation.severity,
        category="assurance",
        applicability=observation.applicability,
        value=observation.value,
        note=observation.note,
        recommendation=observation.recommendation,
        scoring_rationale=(
            "Assurance controls are policy-evaluated separately and never alter "
            "the response-profile score."
        ),
        citation_keys=observation.citation_keys,
        standards=tuple(mapping.label for mapping in mappings),
        evidence_mappings=mappings,
    )


def _evaluate_hsts(
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> _Evaluation:
    del headers
    if urlparse(final_url).scheme != "https":
        return _Evaluation(
            "warning",
            "high",
            "HSTS is ignored when received over an insecure HTTP connection.",
            0.25,
        )

    max_age = _parse_max_age(value)
    if max_age is None:
        return _Evaluation("warning", "high", "max-age is missing or invalid.", 0.25)
    if max_age < 31_536_000:
        return _Evaluation(
            "warning",
            "medium",
            "max-age is below the one-year ASVS baseline.",
            0.5,
        )
    if "includesubdomains" not in value.lower():
        return _Evaluation(
            "warning",
            "low",
            "The one-year max-age baseline is met; includeSubDomains is absent.",
            0.75,
        )
    return _Evaluation("pass", "info", "One-year max-age and includeSubDomains are present.", 1.0)


def _evaluate_csp(
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> _Evaluation:
    del headers, final_url
    directives = _parse_csp(value)
    script_sources = directives.get("script-src", directives.get("default-src", ()))
    if "script-src" not in directives and "default-src" not in directives:
        return _Evaluation(
            "warning",
            "high",
            "The policy does not define script-src or a default-src fallback.",
            0.25,
        )

    weak_script_sources = {"*", "'unsafe-eval'"}
    if any(source in weak_script_sources for source in script_sources):
        return _Evaluation(
            "warning",
            "high",
            "The effective script policy contains a wildcard or unsafe-eval.",
            0.25,
        )

    has_nonce_or_hash = any(
        source.startswith("'nonce-") or source.startswith("'sha")
        for source in script_sources
    )
    if "'unsafe-inline'" in script_sources and not has_nonce_or_hash:
        return _Evaluation(
            "warning",
            "high",
            "The effective script policy allows unsafe-inline without a nonce or hash.",
            0.4,
        )

    missing = [
        directive
        for directive in ("object-src", "base-uri")
        if directive not in directives
    ]
    if missing:
        return _Evaluation(
            "warning",
            "medium",
            "Policy is present but missing defence-in-depth directives: " + ", ".join(missing) + ".",
            0.75,
        )
    return _Evaluation("pass", "info", "No high-risk script source pattern was detected.", 1.0)


def _evaluate_x_content_type_options(
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> _Evaluation:
    del headers, final_url
    if value.lower() == "nosniff":
        return _Evaluation("pass", "info", "nosniff is set.", 1.0)
    return _Evaluation("warning", "medium", "The expected value is nosniff.", 0.25)


def _evaluate_x_frame_options(
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> _Evaluation:
    del final_url
    normalized = value.lower()
    if normalized in {"deny", "sameorigin"}:
        return _Evaluation("pass", "info", "A recognized legacy framing policy is set.", 1.0)
    if _has_frame_ancestors(headers):
        return _Evaluation(
            "warning",
            "low",
            "The legacy value is unusual, but CSP frame-ancestors is present.",
            0.75,
        )
    return _Evaluation("warning", "medium", "Use DENY or SAMEORIGIN for legacy compatibility.", 0.25)


def _evaluate_referrer_policy(
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> _Evaluation:
    del headers, final_url
    selected = value.split(",")[-1].strip().lower()
    strict_values = {
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    if selected in strict_values:
        return _Evaluation("pass", "info", f"Effective policy is {selected}.", 1.0)
    if selected == "unsafe-url":
        return _Evaluation("warning", "high", "unsafe-url can expose full URLs across origins.", 0.0)
    return _Evaluation(
        "warning",
        "medium",
        "The policy should be reviewed against URL and privacy requirements.",
        0.5,
    )


def _evaluate_permissions_policy(
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> _Evaluation:
    del headers, final_url
    if not value.strip():
        return _Evaluation("warning", "medium", "The policy is empty.", 0.0)
    if "=*" in value.replace(" ", ""):
        return _Evaluation(
            "warning",
            "medium",
            "At least one feature appears broadly available; review the allowlist.",
            0.5,
        )
    if "=()" in value.replace(" ", ""):
        return _Evaluation(
            "pass",
            "info",
            "The policy explicitly disables at least one browser feature; verify completeness manually.",
            1.0,
        )
    return _Evaluation(
        "warning",
        "low",
        "A policy is present, but feature necessity cannot be inferred from one response.",
        0.75,
    )


def _evaluate_coop(
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> _Evaluation:
    del headers, final_url
    if value.lower() in {"same-origin", "same-origin-allow-popups"}:
        return _Evaluation("pass", "info", "A recognized opener isolation value is set.", 1.0)
    return _Evaluation("warning", "medium", "The value does not provide strong opener isolation.", 0.25)


def _evaluate_corp(
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> _Evaluation:
    del headers, final_url
    normalized = value.lower()
    if normalized in {"same-origin", "same-site"}:
        return _Evaluation("pass", "info", f"Restrictive resource policy {normalized} is set.", 1.0)
    if normalized == "cross-origin":
        return _Evaluation(
            "warning",
            "medium",
            "cross-origin is valid but does not restrict resource loading.",
            0.25,
        )
    return _Evaluation("warning", "medium", "The value is not recognized.", 0.0)


def _evaluate_coep(
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> _Evaluation:
    del headers, final_url
    if value.lower() in {"require-corp", "credentialless"}:
        return _Evaluation("pass", "info", "A recognized embedder isolation value is set.", 1.0)
    return _Evaluation("warning", "medium", "The value is not recognized.", 0.0)


def _evaluate_cache_control(
    value: str,
    headers: Mapping[str, str],
    final_url: str,
) -> _Evaluation:
    del headers, final_url
    directives = {item.strip().lower() for item in value.split(",")}
    if "no-store" in directives:
        return _Evaluation("pass", "info", "no-store is set.", 1.0)
    if "private" in directives:
        return _Evaluation(
            "warning",
            "low",
            "private prevents shared caching but still permits private browser storage.",
            0.75,
        )
    return _Evaluation(
        "warning",
        "low",
        "Caching may be intentional; review whether this response contains sensitive data.",
        0.5,
    )


def _finding(
    rule: HeaderRule,
    policy: RulePolicy,
    status: str,
    severity: str,
    category: str,
    value: str | None,
    note: str,
    credit_ratio: float,
) -> HeaderFinding:
    mappings = mappings_for_control(rule.key)
    return HeaderFinding(
        key=rule.key,
        name=rule.name,
        status=status,
        severity=severity,
        category=category,
        applicability=policy.applicability.value,
        value=value,
        note=note,
        recommendation=rule.recommendation,
        scoring_rationale=policy.rationale,
        citation_keys=rule.citation_keys,
        standards=tuple(mapping.label for mapping in mappings),
        evidence_mappings=mappings,
        points=round(policy.weight * credit_ratio, 2),
        max_points=policy.weight,
    )


def _parse_max_age(value: str) -> int | None:
    for directive in value.split(";"):
        name, separator, raw_value = directive.strip().partition("=")
        if name.lower() != "max-age":
            continue
        if not separator:
            return None
        try:
            return int(raw_value)
        except ValueError:
            return None
    return None


def _parse_csp(value: str) -> dict[str, tuple[str, ...]]:
    directives: dict[str, tuple[str, ...]] = {}
    for raw_directive in value.split(";"):
        parts = raw_directive.strip().lower().split()
        if not parts:
            continue
        directives[parts[0]] = tuple(parts[1:])
    return directives


def _has_frame_ancestors(headers: Mapping[str, str]) -> bool:
    csp = _parse_csp(headers.get("content-security-policy", ""))
    return "frame-ancestors" in csp


def _weighted_score(findings: list[HeaderFinding]) -> int:
    scored = [finding for finding in findings if finding.category == "scored"]
    max_points = sum(finding.max_points for finding in scored)
    if max_points == 0:
        return 0
    points = sum(finding.points for finding in scored)
    return round(100 * points / max_points)


def _score_summary(score: int) -> str:
    if score >= 85:
        return "Strong"
    if score >= 60:
        return "Moderate"
    if score >= 35:
        return "Needs Review"
    return "Weak"


_EVALUATORS = {
    "strict-transport-security": _evaluate_hsts,
    "content-security-policy": _evaluate_csp,
    "x-content-type-options": _evaluate_x_content_type_options,
    "x-frame-options": _evaluate_x_frame_options,
    "referrer-policy": _evaluate_referrer_policy,
    "permissions-policy": _evaluate_permissions_policy,
    "cross-origin-opener-policy": _evaluate_coop,
    "cross-origin-resource-policy": _evaluate_corp,
    "cross-origin-embedder-policy": _evaluate_coep,
    "cache-control": _evaluate_cache_control,
}
