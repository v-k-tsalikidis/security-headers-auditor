"""Bounded, explicit route-level comparison over the existing audit engine."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from . import METHODOLOGY_VERSION
from .auditor import AuditResult, HeaderFinding, audit_headers, normalize_target
from .compliance import MAPPING_SET_VERSION
from .profiles import ProfileName


ROUTE_COMPARISON_SCHEMA_VERSION = "1.0"
ROUTE_COMPARISON_ARTIFACT = "security-headers-auditor.route-comparison"
MAX_ROUTE_COUNT = 25


class RouteComparisonConfigurationError(ValueError):
    """Raised when a route-comparison manifest exceeds its safe contract."""


@dataclass(frozen=True)
class RouteDefinition:
    id: str
    path: str
    profile: ProfileName
    url: str


@dataclass(frozen=True)
class RouteComparisonConfig:
    schema_version: str
    name: str
    origin: str
    routes: tuple[RouteDefinition, ...]


@dataclass(frozen=True)
class RouteAssessment:
    route: RouteDefinition
    result: AuditResult


@dataclass(frozen=True)
class RouteControlState:
    route_id: str
    status: str
    severity: str
    points: float
    max_points: int


@dataclass(frozen=True)
class RouteControlVariance:
    profile: ProfileName
    control_key: str
    control_name: str
    states: tuple[RouteControlState, ...]


@dataclass(frozen=True)
class RouteComparisonRun:
    config: RouteComparisonConfig
    assessments: tuple[RouteAssessment, ...]
    variances: tuple[RouteControlVariance, ...]
    operational_errors: tuple[str, ...]

    @property
    def exit_code(self) -> int:
        return 2 if self.operational_errors else 0


AuditFunction = Callable[..., AuditResult]


def load_route_comparison(path: Path) -> RouteComparisonConfig:
    """Load and validate one explicit route-comparison manifest."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RouteComparisonConfigurationError(
            f"Cannot read route comparison manifest {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise RouteComparisonConfigurationError(
            "Route comparison manifest is not valid JSON: "
            f"line {exc.lineno}, column {exc.colno}."
        ) from exc
    return parse_route_comparison(payload)


def parse_route_comparison(payload: dict[str, Any]) -> RouteComparisonConfig:
    """Parse a single-origin, operator-supplied route set before any request."""
    if not isinstance(payload, dict):
        raise RouteComparisonConfigurationError(
            "Route comparison manifest root must be a JSON object."
        )
    _reject_unknown_keys(payload, {"schema_version", "name", "origin", "routes"})
    schema_version = _required_string(payload, "schema_version", "manifest")
    if schema_version != ROUTE_COMPARISON_SCHEMA_VERSION:
        raise RouteComparisonConfigurationError(
            "Unsupported route comparison schema "
            f"{schema_version}; expected {ROUTE_COMPARISON_SCHEMA_VERSION}."
        )
    name = _required_string(payload, "name", "manifest", maximum=120)
    origin = _parse_origin(_required_string(payload, "origin", "manifest"))
    routes_payload = payload.get("routes")
    if not isinstance(routes_payload, list):
        raise RouteComparisonConfigurationError("Manifest routes must be a JSON array.")
    if not 2 <= len(routes_payload) <= MAX_ROUTE_COUNT:
        raise RouteComparisonConfigurationError(
            f"Manifest requires between 2 and {MAX_ROUTE_COUNT} explicit routes."
        )

    routes = tuple(_parse_route(item, origin) for item in routes_payload)
    ids = [route.id for route in routes]
    if len(set(ids)) != len(ids):
        raise RouteComparisonConfigurationError("Every route id must be unique.")
    paths = [route.path for route in routes]
    if len(set(paths)) != len(paths):
        raise RouteComparisonConfigurationError("Every route path must be unique.")
    return RouteComparisonConfig(
        schema_version=schema_version,
        name=name,
        origin=origin,
        routes=routes,
    )


def run_route_comparison(
    config: RouteComparisonConfig,
    audit_function: AuditFunction = audit_headers,
) -> RouteComparisonRun:
    """Audit exactly the configured routes and compare scored states by profile."""
    assessments: list[RouteAssessment] = []
    operational_errors: list[str] = []
    for route in config.routes:
        result = audit_function(
            route.url,
            profile=route.profile.value,
            include_query=False,
            allow_cross_origin_redirects=False,
        )
        assessment = RouteAssessment(route=route, result=result)
        assessments.append(assessment)
        if result.error:
            operational_errors.append(f"{route.id}: audit failed: {result.error}")

    return RouteComparisonRun(
        config=config,
        assessments=tuple(assessments),
        variances=_control_variances(tuple(assessments)),
        operational_errors=tuple(operational_errors),
    )


def route_comparison_dict(run: RouteComparisonRun) -> dict[str, Any]:
    """Return a compact report that deliberately omits raw header values."""
    profile_groups = [
        {
            "profile": profile.value,
            "route_ids": [
                assessment.route.id
                for assessment in run.assessments
                if assessment.route.profile == profile
            ],
            "successful_route_count": sum(
                1
                for assessment in run.assessments
                if assessment.route.profile == profile and not assessment.result.error
            ),
        }
        for profile in ProfileName
        if any(assessment.route.profile == profile for assessment in run.assessments)
    ]
    return {
        "schema_version": ROUTE_COMPARISON_SCHEMA_VERSION,
        "artifact": ROUTE_COMPARISON_ARTIFACT,
        "methodology_version": METHODOLOGY_VERSION,
        "mapping_set_version": MAPPING_SET_VERSION,
        "name": run.config.name,
        "origin": run.config.origin,
        "profile_groups": profile_groups,
        "routes": [_route_summary(assessment) for assessment in run.assessments],
        "control_variances": [
            {
                "profile": variance.profile.value,
                "control_key": variance.control_key,
                "control_name": variance.control_name,
                "states": [
                    {
                        "route_id": state.route_id,
                        "status": state.status,
                        "severity": state.severity,
                        "points": state.points,
                        "max_points": state.max_points,
                    }
                    for state in variance.states
                ],
            }
            for variance in run.variances
        ],
        "operational_errors": list(run.operational_errors),
        "limitations": [
            "Only operator-supplied routes were assessed; this mode does not crawl or discover endpoints.",
            "A control variance is a review signal, not a vulnerability, policy failure, or compliance decision.",
            "The summary omits raw response-header values and does not prove browser runtime behavior or route coverage outside the manifest.",
        ],
    }


def render_route_comparison_json(run: RouteComparisonRun) -> str:
    return json.dumps(route_comparison_dict(run), indent=2, sort_keys=True) + "\n"


def render_route_comparison_markdown(run: RouteComparisonRun) -> str:
    """Render a readable comparison without emitting untrusted header values."""
    lines = [
        "# Security Headers Route Comparison",
        "",
        f"- Scope name: `{_escape_markdown(run.config.name)}`",
        f"- Origin: `{_escape_markdown(run.config.origin)}`",
        f"- Methodology version: `{METHODOLOGY_VERSION}`",
        "",
        "Only the explicit routes in the manifest were requested. Control variance is a review "
        "signal, not a vulnerability, policy failure, or compliance decision.",
        "",
        "## Route Summary",
        "",
        "| Route | Path | Declared profile | HTTP status | Score | Summary |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for assessment in run.assessments:
        result = assessment.result
        status = str(result.status_code) if result.status_code is not None else "-"
        score = str(result.score) if not result.error else "-"
        summary = result.summary if not result.error else f"Operational error: {result.error}"
        lines.append(
            "| "
            f"`{_escape_markdown(assessment.route.id)}` | "
            f"`{_escape_markdown(assessment.route.path)}` | "
            f"`{assessment.route.profile.value}` | {status} | {score} | "
            f"{_escape_markdown(summary)} |"
        )

    lines.extend(["", "## Profile Control Variances", ""])
    if not run.variances:
        lines.append(
            "No scored-control variance was observed among successful routes that share a declared profile."
        )
    else:
        lines.extend(
            [
                "| Profile | Control | Route states |",
                "| --- | --- | --- |",
            ]
        )
        for variance in run.variances:
            states = "; ".join(
                f"`{_escape_markdown(state.route_id)}`: {state.status}/{state.severity} "
                f"({state.points:g}/{state.max_points})"
                for state in variance.states
            )
            lines.append(
                f"| `{variance.profile.value}` | `{variance.control_key}` | {states} |"
            )

    if run.operational_errors:
        lines.extend(["", "## Operational Errors", ""])
        lines.extend(f"- {_escape_markdown(error)}" for error in run.operational_errors)
    lines.extend(
        [
            "",
            "The compact comparison omits raw response-header values. Use individual reports "
            "only in an authorized, controlled storage location when detailed evidence is required.",
            "",
        ]
    )
    return "\n".join(lines)


def _parse_origin(value: str) -> str:
    try:
        normalized = normalize_target(value)
        parsed = urlparse(normalized)
        _ = parsed.port
    except ValueError as exc:
        raise RouteComparisonConfigurationError(f"Invalid manifest origin: {exc}") from exc
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise RouteComparisonConfigurationError(
            "Manifest origin must contain scheme and host only, without a path, query, or fragment."
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc}"


def _parse_route(item: Any, origin: str) -> RouteDefinition:
    if not isinstance(item, dict):
        raise RouteComparisonConfigurationError("Each route must be a JSON object.")
    _reject_unknown_keys(item, {"id", "path", "profile"}, "route")
    route_id = _required_string(item, "id", "route", maximum=120)
    path = _parse_route_path(_required_string(item, "path", "route"))
    profile_value = _required_string(item, "profile", "route")
    try:
        profile = ProfileName(profile_value)
    except ValueError as exc:
        raise RouteComparisonConfigurationError(
            "Route profile must be one of: app, api, brochure."
        ) from exc
    return RouteDefinition(
        id=route_id,
        path=path,
        profile=profile,
        url=f"{origin}{path}",
    )


def _parse_route_path(value: str) -> str:
    if not value.startswith("/") or value.startswith("//"):
        raise RouteComparisonConfigurationError(
            "Route path must be an origin-relative path beginning with one slash."
        )
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc or parsed.params or parsed.query or parsed.fragment:
        raise RouteComparisonConfigurationError(
            "Route path must not contain an origin, parameters, query, or fragment."
        )
    if value != parsed.path:
        raise RouteComparisonConfigurationError(
            "Route path must not contain an empty query or fragment delimiter."
        )
    return parsed.path


def _control_variances(
    assessments: tuple[RouteAssessment, ...],
) -> tuple[RouteControlVariance, ...]:
    grouped: dict[tuple[ProfileName, str], list[tuple[RouteAssessment, HeaderFinding]]] = {}
    for assessment in assessments:
        if assessment.result.error:
            continue
        for finding in assessment.result.findings:
            if finding.category != "scored":
                continue
            grouped.setdefault(
                (assessment.route.profile, finding.key), []
            ).append((assessment, finding))

    variances: list[RouteControlVariance] = []
    for (profile, control_key), items in grouped.items():
        if len(items) < 2:
            continue
        states = tuple(
            RouteControlState(
                route_id=assessment.route.id,
                status=finding.status,
                severity=finding.severity,
                points=finding.points,
                max_points=finding.max_points,
            )
            for assessment, finding in items
        )
        signatures = {
            (state.status, state.severity, state.points, state.max_points)
            for state in states
        }
        if len(signatures) > 1:
            variances.append(
                RouteControlVariance(
                    profile=profile,
                    control_key=control_key,
                    control_name=items[0][1].name,
                    states=states,
                )
            )
    return tuple(variances)


def _route_summary(assessment: RouteAssessment) -> dict[str, Any]:
    result = assessment.result
    return {
        "id": assessment.route.id,
        "path": assessment.route.path,
        "declared_profile": assessment.route.profile.value,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "score": result.score if not result.error else None,
        "summary": result.summary,
        "error": result.error,
        "scored_controls": [
            {
                "key": finding.key,
                "status": finding.status,
                "severity": finding.severity,
                "points": finding.points,
                "max_points": finding.max_points,
            }
            for finding in result.findings
            if finding.category == "scored"
        ],
    }


def _required_string(
    payload: dict[str, Any],
    field: str,
    context: str,
    maximum: int | None = None,
) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise RouteComparisonConfigurationError(
            f"{context.capitalize()} requires a non-empty {field}."
        )
    value = value.strip()
    if maximum is not None and len(value) > maximum:
        raise RouteComparisonConfigurationError(
            f"{context.capitalize()} {field} exceeds {maximum} characters."
        )
    return value


def _reject_unknown_keys(
    payload: dict[str, Any],
    allowed: set[str],
    context: str = "manifest",
) -> None:
    unknown = set(payload) - allowed
    if unknown:
        raise RouteComparisonConfigurationError(
            f"Unknown {context} field(s): {', '.join(sorted(unknown))}."
        )


def _escape_markdown(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )
