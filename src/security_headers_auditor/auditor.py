"""Core HTTP security header checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


RECOMMENDED_HEADERS: dict[str, str] = {
    "strict-transport-security": "Encourages HTTPS-only access after first successful connection.",
    "content-security-policy": "Helps reduce content injection and cross-site scripting risk.",
    "x-content-type-options": "Helps prevent MIME sniffing.",
    "x-frame-options": "Helps reduce clickjacking risk.",
    "referrer-policy": "Controls how much referrer information is shared.",
    "permissions-policy": "Restricts browser features available to the page.",
    "cross-origin-opener-policy": "Supports cross-origin isolation and window separation.",
}


@dataclass(frozen=True)
class HeaderFinding:
    name: str
    status: str
    value: str | None
    note: str


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

    normalized_headers = {key.lower(): value for key, value in raw_headers.items()}
    findings: list[HeaderFinding] = []

    for header_name, purpose in RECOMMENDED_HEADERS.items():
        value = normalized_headers.get(header_name)
        if value:
            findings.append(
                HeaderFinding(
                    name=_canonical_header_name(header_name),
                    status="present",
                    value=value,
                    note=purpose,
                )
            )
        else:
            findings.append(
                HeaderFinding(
                    name=_canonical_header_name(header_name),
                    status="missing",
                    value=None,
                    note=purpose,
                )
            )

    score = round(
        100
        * sum(1 for finding in findings if finding.status == "present")
        / len(RECOMMENDED_HEADERS)
    )
    summary = _score_summary(score)

    return AuditResult(
        target=target,
        final_url=final_url,
        status_code=status_code,
        score=score,
        summary=summary,
        findings=findings,
    )


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

