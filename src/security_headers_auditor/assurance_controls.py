"""Contextual reporting and cross-origin isolation assurance controls."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Mapping
from urllib.parse import urljoin, urlparse, urlunparse

from .csp import parse_csp


class AssuranceExpectation(str, Enum):
    OBSERVE = "observe"
    RECOMMENDED = "recommended"
    REQUIRED = "required"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class ControlObservation:
    key: str
    name: str
    status: str
    severity: str
    applicability: str
    value: str | None
    note: str
    recommendation: str
    citation_keys: tuple[str, ...]


def parse_expectation(value: str) -> AssuranceExpectation:
    try:
        return AssuranceExpectation(value.strip().lower().replace("-", "_"))
    except ValueError as exc:
        allowed = ", ".join(item.value for item in AssuranceExpectation)
        raise ValueError(
            f"Unsupported assurance expectation {value!r}; choose {allowed}."
        ) from exc


def analyze_reporting_readiness(
    headers: Mapping[str, str],
    final_url: str,
    expectation: AssuranceExpectation | str = AssuranceExpectation.OBSERVE,
) -> tuple[ControlObservation, ...]:
    """Assess endpoint syntax and CSP-to-endpoint reporting linkage."""
    expected = (
        expectation
        if isinstance(expectation, AssuranceExpectation)
        else parse_expectation(expectation)
    )
    if expected == AssuranceExpectation.NOT_APPLICABLE:
        return (
            _not_applicable(
                "reporting-endpoints",
                "Reporting Endpoints",
                "Reporting readiness was explicitly marked not applicable.",
            ),
            _not_applicable(
                "reporting-readiness",
                "CSP Reporting Readiness",
                "CSP violation reporting was explicitly marked not applicable.",
            ),
        )

    modern_raw = headers.get("reporting-endpoints")
    modern, modern_errors = _parse_reporting_endpoints(modern_raw, final_url)
    legacy_raw = headers.get("report-to")
    legacy, legacy_errors = _parse_legacy_report_to(legacy_raw, final_url)

    endpoint_value = _format_endpoint_groups(modern or legacy)
    if modern_errors or legacy_errors:
        endpoint_observation = ControlObservation(
            key="reporting-endpoints",
            name="Reporting Endpoints",
            status="warning",
            severity="high" if expected == AssuranceExpectation.REQUIRED else "medium",
            applicability=expected.value,
            value=endpoint_value or None,
            note=" ".join((*modern_errors, *legacy_errors)),
            recommendation=(
                "Define Reporting-Endpoints as a valid Structured Field dictionary "
                "whose members resolve to trustworthy endpoints. Retain Report-To "
                "only as a documented legacy compatibility mechanism."
            ),
            citation_keys=("w3c-reporting", "w3c-reporting-legacy"),
        )
    elif modern:
        legacy_note = (
            " A legacy Report-To configuration was also observed."
            if legacy
            else ""
        )
        endpoint_observation = ControlObservation(
            key="reporting-endpoints",
            name="Reporting Endpoints",
            status="pass",
            severity="info",
            applicability=expected.value,
            value=_format_endpoint_groups(modern),
            note=(
                f"{len(modern)} valid modern reporting endpoint group(s) observed."
                f"{legacy_note}"
            ),
            recommendation=(
                "Keep endpoint ownership, retention, access control, availability, "
                "and privacy handling documented and tested outside this response audit."
            ),
            citation_keys=("w3c-reporting", "asvs-5"),
        )
    elif legacy:
        endpoint_observation = ControlObservation(
            key="reporting-endpoints",
            name="Reporting Endpoints",
            status="review",
            severity="medium" if expected == AssuranceExpectation.REQUIRED else "low",
            applicability=expected.value,
            value=_format_endpoint_groups(legacy),
            note=(
                "Only the legacy Report-To mechanism was observed. It provides "
                "compatibility evidence, not modern Reporting-Endpoints readiness."
            ),
            recommendation=(
                "Introduce Reporting-Endpoints and verify browser compatibility before "
                "retiring any legacy Report-To fallback."
            ),
            citation_keys=("w3c-reporting", "w3c-reporting-legacy"),
        )
    else:
        status, severity = _absence_status(expected)
        endpoint_observation = ControlObservation(
            key="reporting-endpoints",
            name="Reporting Endpoints",
            status=status,
            severity=severity,
            applicability=expected.value,
            value=None,
            note="No Reporting-Endpoints or legacy Report-To configuration was observed.",
            recommendation=(
                "Define a trustworthy reporting endpoint only when the organization "
                "has an owned collector, documented data handling, and an operational "
                "triage process."
            ),
            citation_keys=("w3c-reporting", "asvs-5"),
        )

    csp_values = tuple(
        value
        for key in ("content-security-policy", "content-security-policy-report-only")
        if (value := headers.get(key))
    )
    report_to_groups: set[str] = set()
    report_uris: set[str] = set()
    for csp_value in csp_values:
        parsed_csp = parse_csp(csp_value)
        report_to_groups.update(parsed_csp.directive_values("report-to"))
        report_uris.update(parsed_csp.directive_values("report-uri"))

    configured_groups = set(modern) | set(legacy)
    unlinked = sorted(report_to_groups - configured_groups)
    if unlinked:
        linkage = ControlObservation(
            key="reporting-readiness",
            name="CSP Reporting Readiness",
            status="warning",
            severity="high",
            applicability=expected.value,
            value=", ".join(sorted(report_to_groups)),
            note=(
                "CSP report-to references endpoint group(s) that were not validly "
                "configured: " + ", ".join(unlinked) + "."
            ),
            recommendation=(
                "Make every CSP report-to group match a valid Reporting-Endpoints "
                "member, then test delivery and collector processing separately."
            ),
            citation_keys=("w3c-csp3", "w3c-reporting", "asvs-5"),
        )
    elif report_to_groups and modern:
        linkage = ControlObservation(
            key="reporting-readiness",
            name="CSP Reporting Readiness",
            status="pass",
            severity="info",
            applicability=expected.value,
            value=", ".join(sorted(report_to_groups)),
            note=(
                "CSP report-to group references are linked to valid modern reporting "
                "endpoint definitions. Delivery and triage remain unverified."
            ),
            recommendation=(
                "Exercise report delivery in a controlled browser test and monitor "
                "collector availability, sanitization, retention, and alert routing."
            ),
            citation_keys=("w3c-csp3", "w3c-reporting", "asvs-5"),
        )
    elif report_to_groups and legacy:
        linkage = ControlObservation(
            key="reporting-readiness",
            name="CSP Reporting Readiness",
            status="review",
            severity="medium" if expected == AssuranceExpectation.REQUIRED else "low",
            applicability=expected.value,
            value=", ".join(sorted(report_to_groups)),
            note="CSP reporting is linked only through the legacy Report-To mechanism.",
            recommendation="Add a modern Reporting-Endpoints definition for the CSP group.",
            citation_keys=("w3c-csp3", "w3c-reporting-legacy", "asvs-5"),
        )
    elif report_uris:
        resolved_report_uris = {
            urljoin(final_url, report_uri)
            for report_uri in report_uris
        }
        untrustworthy_report_uris = {
            report_uri
            for report_uri in resolved_report_uris
            if not _is_potentially_trustworthy(report_uri)
        }
        if untrustworthy_report_uris:
            linkage = ControlObservation(
                key="reporting-readiness",
                name="CSP Reporting Readiness",
                status="warning",
                severity="high",
                applicability=expected.value,
                value=", ".join(
                    sorted(_redact_url(item) for item in resolved_report_uris)
                ),
                note="CSP report-uri includes a non-trustworthy reporting destination.",
                recommendation=(
                    "Remove insecure reporting destinations and plan a "
                    "compatibility-tested migration to Reporting-Endpoints."
                ),
                citation_keys=("w3c-csp3", "w3c-reporting", "asvs-5"),
            )
            return endpoint_observation, linkage
        linkage = ControlObservation(
            key="reporting-readiness",
            name="CSP Reporting Readiness",
            status="review",
            severity="medium" if expected == AssuranceExpectation.REQUIRED else "low",
            applicability=expected.value,
            value=", ".join(
                sorted(_redact_url(item) for item in resolved_report_uris)
            ),
            note=(
                "Only the legacy CSP report-uri directive was observed. Endpoint "
                "reachability and collector behavior were not tested."
            ),
            recommendation=(
                "Plan a compatibility-tested migration to report-to with "
                "Reporting-Endpoints while retaining report-uri only where required."
            ),
            citation_keys=("w3c-csp3", "w3c-reporting", "asvs-5"),
        )
    else:
        status, severity = _absence_status(expected)
        linkage = ControlObservation(
            key="reporting-readiness",
            name="CSP Reporting Readiness",
            status=status,
            severity=severity,
            applicability=expected.value,
            value=None,
            note="No CSP report-to or report-uri directive was observed.",
            recommendation=(
                "Configure CSP reporting only with an owned collector and a documented "
                "operational response process. Presence alone is not assurance."
            ),
            citation_keys=("w3c-csp3", "w3c-reporting", "asvs-5"),
        )

    return endpoint_observation, linkage


def analyze_cross_origin_isolation(
    headers: Mapping[str, str],
    expectation: AssuranceExpectation | str = AssuranceExpectation.OBSERVE,
) -> ControlObservation:
    """Assess response-level readiness for a cross-origin isolated document."""
    expected = (
        expectation
        if isinstance(expectation, AssuranceExpectation)
        else parse_expectation(expectation)
    )
    if expected == AssuranceExpectation.NOT_APPLICABLE:
        return _not_applicable(
            "cross-origin-isolation-bundle",
            "Cross-Origin Isolation Bundle",
            "Cross-origin isolation was explicitly marked not applicable.",
        )

    coop = headers.get("cross-origin-opener-policy", "").strip().lower()
    coep = headers.get("cross-origin-embedder-policy", "").strip().lower()
    corp = headers.get("cross-origin-resource-policy", "").strip().lower()
    evidence = "; ".join(
        item
        for item in (
            f"COOP={coop}" if coop else "",
            f"COEP={coep}" if coep else "",
            f"CORP={corp}" if corp else "",
        )
        if item
    )

    coop_ready = coop == "same-origin"
    coep_ready = coep in {"require-corp", "credentialless"}
    corp_valid = not corp or corp in {"same-origin", "same-site", "cross-origin"}

    if coop_ready and coep_ready and corp_valid:
        return ControlObservation(
            key="cross-origin-isolation-bundle",
            name="Cross-Origin Isolation Bundle",
            status="pass",
            severity="info",
            applicability=expected.value,
            value=evidence,
            note=(
                "The observed document response declares COOP and COEP values consistent "
                "with response-level cross-origin isolation readiness. Actual "
                "crossOriginIsolated state and dependent-resource compatibility are unverified."
            ),
            recommendation=(
                "Verify the complete resource graph, CORS/CORP behavior, popup and "
                "federated sign-in workflows, and window.crossOriginIsolated in browser QA."
            ),
            citation_keys=("w3c-post-spectre", "whatwg-html", "whatwg-fetch", "asvs-5"),
        )

    if not coop and not coep:
        status, severity = _absence_status(expected)
        return ControlObservation(
            key="cross-origin-isolation-bundle",
            name="Cross-Origin Isolation Bundle",
            status=status,
            severity=severity,
            applicability=expected.value,
            value=None,
            note=(
                "No COOP/COEP isolation pair was observed. This is not automatically a "
                "defect unless the document requires cross-origin isolation."
            ),
            recommendation=(
                "Enable the bundle only after documenting the capability requirement "
                "and testing third-party resources, payments, popups, and sign-in flows."
            ),
            citation_keys=("w3c-post-spectre", "whatwg-html", "whatwg-fetch"),
        )

    defects: list[str] = []
    if not coop_ready:
        defects.append("COOP must be same-origin for full isolation readiness")
    if not coep_ready:
        defects.append("COEP must be require-corp or credentialless")
    if not corp_valid:
        defects.append("the observed CORP value is invalid")
    return ControlObservation(
        key="cross-origin-isolation-bundle",
        name="Cross-Origin Isolation Bundle",
        status="warning" if expected == AssuranceExpectation.REQUIRED else "review",
        severity="high" if expected == AssuranceExpectation.REQUIRED else "medium",
        applicability=expected.value,
        value=evidence or None,
        note="Partial or inconsistent isolation configuration: " + "; ".join(defects) + ".",
        recommendation=(
            "Treat COOP, COEP, resource CORS/CORP behavior, and application compatibility "
            "as one deployment decision rather than independent checkbox headers."
        ),
        citation_keys=("w3c-post-spectre", "whatwg-html", "whatwg-fetch", "asvs-5"),
    )


def _not_applicable(key: str, name: str, note: str) -> ControlObservation:
    return ControlObservation(
        key=key,
        name=name,
        status="not_applicable",
        severity="info",
        applicability=AssuranceExpectation.NOT_APPLICABLE.value,
        value=None,
        note=note,
        recommendation="No action required for the declared assurance policy.",
        citation_keys=("w3c-reporting",) if key.startswith("reporting") else ("w3c-post-spectre",),
    )


def _absence_status(expectation: AssuranceExpectation) -> tuple[str, str]:
    if expectation == AssuranceExpectation.REQUIRED:
        return "missing", "high"
    if expectation == AssuranceExpectation.RECOMMENDED:
        return "review", "medium"
    return "info", "info"


def _parse_reporting_endpoints(
    raw: str | None,
    base_url: str,
) -> tuple[dict[str, str], tuple[str, ...]]:
    if not raw:
        return {}, ()
    if len(raw) > 16_384:
        return {}, ("Reporting-Endpoints exceeds the 16 KiB analysis limit.",)
    endpoints: dict[str, str] = {}
    errors: list[str] = []
    for member in _split_quoted(raw, ","):
        name, separator, remainder = member.partition("=")
        name = name.strip()
        if not separator or not re.fullmatch(r"[a-z*][a-z0-9_.*-]*", name):
            errors.append(f"Invalid Reporting-Endpoints member: {member.strip()!r}.")
            continue
        if name in endpoints:
            errors.append(f"Duplicate Reporting-Endpoints group: {name!r}.")
            continue
        parsed_value, trailing, error = _parse_quoted_value(remainder.strip())
        if error:
            errors.append(f"Endpoint group {name!r}: {error}")
            continue
        if trailing and not trailing.startswith(";"):
            errors.append(f"Endpoint group {name!r} has invalid trailing data.")
            continue
        resolved = urljoin(base_url, parsed_value)
        if not _is_potentially_trustworthy(resolved):
            errors.append(f"Endpoint group {name!r} does not resolve to a trustworthy URL.")
            continue
        endpoints[name] = resolved
    return endpoints, tuple(errors)


def _parse_legacy_report_to(
    raw: str | None,
    base_url: str,
) -> tuple[dict[str, str], tuple[str, ...]]:
    if not raw:
        return {}, ()
    if len(raw) > 16_384:
        return {}, ("Legacy Report-To exceeds the 16 KiB analysis limit.",)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}, ("Legacy Report-To is not valid JSON.",)
    records = payload if isinstance(payload, list) else [payload]
    groups: dict[str, str] = {}
    errors: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            errors.append("Legacy Report-To entries must be JSON objects.")
            continue
        group = record.get("group", "default")
        max_age = record.get("max_age")
        endpoint_items = record.get("endpoints", [])
        if not isinstance(group, str) or not group:
            errors.append("Legacy Report-To group must be a non-empty string.")
            continue
        if group in groups:
            errors.append(f"Duplicate legacy Report-To group: {group!r}.")
            continue
        if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age <= 0:
            errors.append(
                f"Legacy Report-To group {group!r} has no positive max_age."
            )
            continue
        if not isinstance(endpoint_items, list) or not endpoint_items:
            errors.append(f"Legacy Report-To group {group!r} has no endpoints.")
            continue
        resolved = next(
            (
                urljoin(base_url, url)
                for endpoint in endpoint_items
                if isinstance(endpoint, dict)
                and isinstance((url := endpoint.get("url")), str)
                and _is_potentially_trustworthy(urljoin(base_url, url))
            ),
            None,
        )
        if resolved is None:
            errors.append(f"Legacy Report-To group {group!r} is not trustworthy.")
            continue
        groups[group] = resolved
    return groups, tuple(errors)


def _parse_quoted_value(value: str) -> tuple[str, str, str | None]:
    if not value.startswith('"'):
        return "", value, "endpoint value must be a quoted string."
    result: list[str] = []
    escaped = False
    for index, character in enumerate(value[1:], start=1):
        if escaped:
            if character not in {'"', "\\"}:
                return "", value[index + 1 :], "quoted string contains an invalid escape."
            result.append(character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == '"':
            return "".join(result), value[index + 1 :].strip(), None
        if ord(character) < 0x20 or ord(character) > 0x7E:
            return "", value[index + 1 :], "quoted string contains an invalid character."
        result.append(character)
    return "", "", "quoted string is not terminated."


def _split_quoted(value: str, delimiter: str) -> tuple[str, ...]:
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\" and quoted:
            current.append(character)
            escaped = True
            continue
        if character == '"':
            quoted = not quoted
            current.append(character)
            continue
        if character == delimiter and not quoted:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(character)
    parts.append("".join(current).strip())
    return tuple(part for part in parts if part)


def _is_potentially_trustworthy(url: str) -> bool:
    parsed = urlparse(url)
    if any(character.isspace() or ord(character) < 0x20 for character in url):
        return False
    try:
        parsed.port
    except ValueError:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return (
        parsed.scheme == "http"
        and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    )


def _format_endpoint_groups(groups: Mapping[str, str]) -> str:
    return ", ".join(
        f'{name}="{_redact_url(url)}"'
        for name, url in sorted(groups.items())
    )


def _redact_url(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{display_host}:{port}" if port is not None else display_host
    return urlunparse(
        parsed._replace(
            netloc=netloc,
            query="<redacted>" if parsed.query else "",
            fragment="<redacted>" if parsed.fragment else "",
        )
    )
