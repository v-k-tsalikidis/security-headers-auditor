"""Endpoint profile definitions and conservative response classification."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class ProfileName(str, Enum):
    APP = "app"
    API = "api"
    BROCHURE = "brochure"


class Applicability(str, Enum):
    REQUIRED = "required"
    RECOMMENDED = "recommended"
    INFORMATIONAL = "informational"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class RulePolicy:
    applicability: Applicability
    weight: int
    rationale: str


@dataclass(frozen=True)
class ProfileDefinition:
    name: ProfileName
    label: str
    description: str
    policies: Mapping[str, RulePolicy]


@dataclass(frozen=True)
class ProfileDecision:
    requested: str
    selected: ProfileName
    confidence: str
    evidence: tuple[str, ...]
    manual_override: bool


def _policy(
    applicability: Applicability,
    weight: int,
    rationale: str,
) -> RulePolicy:
    return RulePolicy(applicability=applicability, weight=weight, rationale=rationale)


PROFILE_DEFINITIONS: dict[ProfileName, ProfileDefinition] = {
    ProfileName.APP: ProfileDefinition(
        name=ProfileName.APP,
        label="Authenticated Web Application",
        description=(
            "Browser-rendered application where user state, sensitive workflows, and "
            "cross-origin interactions justify the broadest header baseline."
        ),
        policies={
            "strict-transport-security": _policy(
                Applicability.REQUIRED, 20, "Transport enforcement protects authenticated browser sessions."
            ),
            "content-security-policy": _policy(
                Applicability.REQUIRED, 25, "Executable application content requires a meaningful CSP."
            ),
            "x-content-type-options": _policy(
                Applicability.REQUIRED, 10, "Application resources must not be MIME-sniffed."
            ),
            "x-frame-options": _policy(
                Applicability.RECOMMENDED,
                5,
                "Legacy framing protection remains useful when CSP frame-ancestors is not universal.",
            ),
            "referrer-policy": _policy(
                Applicability.REQUIRED, 10, "Paths and query data may contain sensitive application context."
            ),
            "permissions-policy": _policy(
                Applicability.RECOMMENDED, 10, "Powerful browser features should be explicitly constrained."
            ),
            "cross-origin-opener-policy": _policy(
                Applicability.RECOMMENDED, 10, "Window isolation is valuable for authenticated documents."
            ),
            "cross-origin-resource-policy": _policy(
                Applicability.RECOMMENDED, 10, "Sensitive resources benefit from explicit origin boundaries."
            ),
            "cross-origin-embedder-policy": _policy(
                Applicability.INFORMATIONAL,
                0,
                "Required only when the application intentionally enables cross-origin isolation.",
            ),
            "clear-site-data": _policy(
                Applicability.INFORMATIONAL, 0, "Useful on selected logout or reset endpoints only."
            ),
            "cache-control": _policy(
                Applicability.INFORMATIONAL, 0, "Sensitivity is endpoint-specific and cannot be inferred safely."
            ),
            "x-permitted-cross-domain-policies": _policy(
                Applicability.INFORMATIONAL, 0, "Legacy client exposure is environment-specific."
            ),
            "x-dns-prefetch-control": _policy(
                Applicability.INFORMATIONAL, 0, "Privacy and performance trade-offs are document-specific."
            ),
        },
    ),
    ProfileName.API: ProfileDefinition(
        name=ProfileName.API,
        label="API Response",
        description=(
            "Non-HTML REST, GraphQL, or machine-readable response. Browser document "
            "controls are not scored when they do not affect the response context."
        ),
        policies={
            "strict-transport-security": _policy(
                Applicability.REQUIRED,
                60,
                "HSTS is a host-level browser transport signal and remains relevant to browser-consumed APIs.",
            ),
            "content-security-policy": _policy(
                Applicability.INFORMATIONAL,
                0,
                "Most CSP directives affect rendered documents; API hardening may use default-src 'none' as defence in depth.",
            ),
            "x-content-type-options": _policy(
                Applicability.REQUIRED, 40, "nosniff helps prevent non-HTML data from being interpreted as active content."
            ),
            "x-frame-options": _policy(
                Applicability.NOT_APPLICABLE, 0, "Framing controls do not protect a non-document API response."
            ),
            "referrer-policy": _policy(
                Applicability.NOT_APPLICABLE, 0, "The response does not initiate document referrer behavior."
            ),
            "permissions-policy": _policy(
                Applicability.NOT_APPLICABLE, 0, "The response does not create a document permissions context."
            ),
            "cross-origin-opener-policy": _policy(
                Applicability.NOT_APPLICABLE, 0, "The response does not create a top-level Window."
            ),
            "cross-origin-resource-policy": _policy(
                Applicability.INFORMATIONAL,
                0,
                "CORP can matter for browser resource loading, but API sharing policy is deployment-specific.",
            ),
            "cross-origin-embedder-policy": _policy(
                Applicability.NOT_APPLICABLE, 0, "The response does not create a document embedder policy."
            ),
            "clear-site-data": _policy(
                Applicability.INFORMATIONAL, 0, "Potentially useful on authentication/session termination endpoints."
            ),
            "cache-control": _policy(
                Applicability.INFORMATIONAL,
                0,
                "no-store is important for sensitive responses, but public APIs may intentionally be cacheable.",
            ),
            "x-permitted-cross-domain-policies": _policy(
                Applicability.INFORMATIONAL, 0, "Legacy policy-file handling is deployment-specific."
            ),
            "x-dns-prefetch-control": _policy(
                Applicability.NOT_APPLICABLE, 0, "The response does not create a document prefetch context."
            ),
        },
    ),
    ProfileName.BROCHURE: ProfileDefinition(
        name=ProfileName.BROCHURE,
        label="Public Brochure Site",
        description=(
            "Public HTML content with limited authenticated state. Delivery hardening and "
            "content controls are prioritized without assuming application-only capabilities."
        ),
        policies={
            "strict-transport-security": _policy(
                Applicability.REQUIRED, 30, "Public web delivery should consistently enforce HTTPS."
            ),
            "content-security-policy": _policy(
                Applicability.REQUIRED, 30, "Public scripts and third-party content still require trust boundaries."
            ),
            "x-content-type-options": _policy(
                Applicability.REQUIRED, 15, "Static resources must retain authoritative content types."
            ),
            "x-frame-options": _policy(
                Applicability.RECOMMENDED, 10, "Legacy clickjacking protection supplements CSP frame-ancestors."
            ),
            "referrer-policy": _policy(
                Applicability.REQUIRED, 10, "URL paths and campaign query data should not leak unnecessarily."
            ),
            "permissions-policy": _policy(
                Applicability.RECOMMENDED, 5, "Unused browser capabilities should be constrained."
            ),
            "cross-origin-opener-policy": _policy(
                Applicability.INFORMATIONAL, 0, "Process isolation may be useful but is not a universal brochure-site baseline."
            ),
            "cross-origin-resource-policy": _policy(
                Applicability.INFORMATIONAL, 0, "Resource sharing requirements vary across public assets."
            ),
            "cross-origin-embedder-policy": _policy(
                Applicability.NOT_APPLICABLE, 0, "Cross-origin isolation is rarely required for brochure content."
            ),
            "clear-site-data": _policy(
                Applicability.NOT_APPLICABLE, 0, "A brochure response normally has no sensitive session transition."
            ),
            "cache-control": _policy(
                Applicability.INFORMATIONAL, 0, "Public content often benefits from deliberate caching."
            ),
            "x-permitted-cross-domain-policies": _policy(
                Applicability.INFORMATIONAL, 0, "Legacy policy-file handling is deployment-specific."
            ),
            "x-dns-prefetch-control": _policy(
                Applicability.INFORMATIONAL, 0, "Privacy and performance trade-offs are site-specific."
            ),
        },
    ),
}


def parse_profile(value: str) -> str:
    normalized = value.strip().lower()
    allowed = {"auto", *(profile.value for profile in ProfileName)}
    if normalized not in allowed:
        raise ValueError(f"Unsupported profile: {value}")
    return normalized


def resolve_profile(requested: str, headers: Mapping[str, str]) -> ProfileDecision:
    """Resolve a user-selected profile or conservatively classify one response."""
    requested = parse_profile(requested)
    if requested != "auto":
        selected = ProfileName(requested)
        return ProfileDecision(
            requested=requested,
            selected=selected,
            confidence="explicit",
            evidence=(f"Profile selected by user: {selected.value}.",),
            manual_override=True,
        )

    content_type = headers.get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()
    if _is_api_media_type(media_type):
        return ProfileDecision(
            requested="auto",
            selected=ProfileName.API,
            confidence="high",
            evidence=(f"Machine-readable Content-Type observed: {media_type}.",),
            manual_override=False,
        )

    if media_type == "text/html":
        app_signals = _application_signals(headers)
        if len(app_signals) >= 2:
            return ProfileDecision(
                requested="auto",
                selected=ProfileName.APP,
                confidence="medium",
                evidence=(
                    "HTML response with multiple authenticated-application signals.",
                    *app_signals,
                    "Confirm with --profile because headers cannot prove application purpose.",
                ),
                manual_override=False,
            )
        return ProfileDecision(
            requested="auto",
            selected=ProfileName.BROCHURE,
            confidence="medium",
            evidence=(
                "HTML response without enough authenticated-application signals.",
                "Use --profile app when the endpoint belongs to an authenticated workflow.",
            ),
            manual_override=False,
        )

    label = media_type or "missing Content-Type"
    return ProfileDecision(
        requested="auto",
        selected=ProfileName.BROCHURE,
        confidence="low",
        evidence=(
            f"Response type is ambiguous ({label}); conservative public-web fallback applied.",
            "Select --profile explicitly when endpoint purpose is known.",
        ),
        manual_override=False,
    )


def profile_definition(name: ProfileName | str) -> ProfileDefinition:
    return PROFILE_DEFINITIONS[ProfileName(name)]


def validate_profile_weights() -> None:
    """Raise when a profile's scored policies do not normalize to 100 points."""
    for definition in PROFILE_DEFINITIONS.values():
        weight = sum(policy.weight for policy in definition.policies.values())
        if weight != 100:
            raise ValueError(f"{definition.name.value} profile weights total {weight}, expected 100.")


def _is_api_media_type(media_type: str) -> bool:
    return (
        media_type
        in {
            "application/json",
            "application/graphql-response+json",
            "application/problem+json",
            "application/xml",
            "text/xml",
        }
        or media_type.endswith("+json")
        or media_type.endswith("+xml")
    )


def _application_signals(headers: Mapping[str, str]) -> tuple[str, ...]:
    signals: list[str] = []
    if "set-cookie" in headers:
        signals.append("Set-Cookie response header observed.")
    if "www-authenticate" in headers:
        signals.append("WWW-Authenticate response header observed.")
    cache_control = headers.get("cache-control", "").lower()
    if "private" in cache_control or "no-store" in cache_control:
        signals.append("Private or no-store cache policy observed.")
    return tuple(signals)


validate_profile_weights()
