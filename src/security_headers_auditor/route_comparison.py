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
ROUTE_BASELINE_SCHEMA_VERSION = "1.0"
ROUTE_BASELINE_ARTIFACT = "security-headers-auditor.route-assurance-baseline"
ROUTE_ASSURANCE_ARTIFACT = "security-headers-auditor.route-assurance"
ROUTE_ASSURANCE_REVIEW_SCHEMA_VERSION = "1.0"
ROUTE_ASSURANCE_REVIEW_ARTIFACT = "security-headers-auditor.route-assurance-review"
MAX_ROUTE_COUNT = 25
_BASELINE_STATUSES = {
    "pass",
    "info",
    "observed",
    "not_applicable",
    "review",
    "warning",
    "missing",
    "error",
}
_BASELINE_SEVERITIES = {"info", "low", "medium", "high"}
_ACTIONABLE_STATUSES = {"missing", "warning", "review"}


class RouteComparisonConfigurationError(ValueError):
    """Raised when a route-comparison manifest exceeds its safe contract."""


class RouteBaselineCompatibilityError(ValueError):
    """Raised when a route baseline cannot be safely compared."""


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


@dataclass(frozen=True)
class RouteRegression:
    route_id: str
    code: str
    severity: str
    control_key: str | None
    previous: str | int | float | None
    current: str | int | float | None
    message: str


@dataclass(frozen=True)
class RouteAssuranceRun:
    comparison: RouteComparisonRun
    baseline_schema_version: str | None
    regressions: tuple[RouteRegression, ...]

    @property
    def outcome(self) -> str:
        if self.comparison.operational_errors:
            return "operational_error"
        if self.regressions:
            return "failed"
        return "passed"

    @property
    def exit_code(self) -> int:
        if self.comparison.operational_errors:
            return 2
        if self.regressions:
            return 1
        return 0


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


def load_route_baseline(path: Path) -> dict[str, Any]:
    """Load a separately approved, data-minimized route baseline."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RouteBaselineCompatibilityError(
            f"Cannot read route baseline {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise RouteBaselineCompatibilityError(
            "Route baseline is not valid JSON: "
            f"line {exc.lineno}, column {exc.colno}."
        ) from exc
    validate_route_baseline(payload)
    return payload


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


def run_route_assurance(
    config: RouteComparisonConfig,
    baseline: dict[str, Any] | None = None,
    audit_function: AuditFunction = audit_headers,
) -> RouteAssuranceRun:
    """Compare one explicit route set with an optionally approved baseline."""
    comparison = run_route_comparison(config, audit_function=audit_function)
    baseline_schema_version: str | None = None
    regressions: tuple[RouteRegression, ...] = ()
    if baseline is not None and not comparison.operational_errors:
        baseline_schema_version = validate_route_baseline(baseline)
        regressions = compare_route_baseline(comparison, baseline)
    return RouteAssuranceRun(
        comparison=comparison,
        baseline_schema_version=baseline_schema_version,
        regressions=regressions,
    )


def create_route_baseline(run: RouteComparisonRun) -> dict[str, Any]:
    """Create a candidate baseline only from a complete route run.

    The candidate records drift evidence, not a security pass or risk acceptance.
    Operators must review and explicitly approve it before using it as a baseline.
    """
    if run.operational_errors:
        raise RouteBaselineCompatibilityError(
            "A route baseline candidate requires a complete run with no operational errors."
        )
    return {
        "schema_version": ROUTE_BASELINE_SCHEMA_VERSION,
        "artifact": ROUTE_BASELINE_ARTIFACT,
        "methodology_version": METHODOLOGY_VERSION,
        "mapping_set_version": MAPPING_SET_VERSION,
        "manifest": _manifest_dict(run.config),
        "routes": {
            assessment.route.id: _baseline_route(assessment)
            for assessment in sorted(run.assessments, key=lambda item: item.route.id)
        },
    }


def write_route_baseline(path: Path, run: RouteComparisonRun) -> None:
    """Write one new candidate baseline without replacing an approved artifact."""
    if path.exists():
        raise RouteBaselineCompatibilityError(
            f"Route baseline candidate {path} already exists; review it or choose a new path."
        )
    payload = create_route_baseline(run)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_route_baseline(payload: dict[str, Any]) -> str:
    """Validate a route-baseline artifact without inferring future semantics."""
    if not isinstance(payload, dict):
        raise RouteBaselineCompatibilityError("Route baseline root must be a JSON object.")
    _reject_baseline_unknown_keys(
        payload,
        {
            "schema_version",
            "artifact",
            "methodology_version",
            "mapping_set_version",
            "manifest",
            "routes",
        },
        "route baseline",
    )
    _require_baseline_value(
        payload, "schema_version", ROUTE_BASELINE_SCHEMA_VERSION, "route baseline"
    )
    _require_baseline_value(
        payload, "artifact", ROUTE_BASELINE_ARTIFACT, "route baseline"
    )
    _require_baseline_value(
        payload, "methodology_version", METHODOLOGY_VERSION, "route baseline"
    )
    _require_baseline_value(
        payload, "mapping_set_version", MAPPING_SET_VERSION, "route baseline"
    )
    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        raise RouteBaselineCompatibilityError("Route baseline manifest must be a JSON object.")
    try:
        config = parse_route_comparison(manifest)
    except RouteComparisonConfigurationError as exc:
        raise RouteBaselineCompatibilityError(
            f"Route baseline manifest is invalid: {exc}"
        ) from exc
    routes = payload.get("routes")
    if not isinstance(routes, dict):
        raise RouteBaselineCompatibilityError("Route baseline routes must be a JSON object.")
    expected_routes = {route.id: route for route in config.routes}
    if set(routes) != set(expected_routes):
        raise RouteBaselineCompatibilityError(
            "Route baseline route ids do not exactly match the baseline manifest."
        )
    for route_id, definition in expected_routes.items():
        _validate_baseline_route(route_id, routes[route_id], definition)
    return ROUTE_BASELINE_SCHEMA_VERSION


def compare_route_baseline(
    run: RouteComparisonRun,
    baseline: dict[str, Any],
) -> tuple[RouteRegression, ...]:
    """Return deterministic route drift signals for an approved baseline."""
    validate_route_baseline(baseline)
    if baseline["manifest"] != _manifest_dict(run.config):
        raise RouteBaselineCompatibilityError(
            "Route baseline manifest does not match the current explicit route scope; "
            "review and create a new baseline."
        )
    if run.operational_errors:
        return ()

    regressions: list[RouteRegression] = []
    baseline_routes = baseline["routes"]
    for assessment in sorted(run.assessments, key=lambda item: item.route.id):
        route_id = assessment.route.id
        before = baseline_routes[route_id]
        current = _baseline_route(assessment)
        if current["score"] < before["score"]:
            regressions.append(
                RouteRegression(
                    route_id=route_id,
                    code="score.regressed",
                    severity="high",
                    control_key=None,
                    previous=before["score"],
                    current=current["score"],
                    message="Route score decreased from the approved baseline.",
                )
            )

        previous_controls = before["scored_controls"]
        current_controls = current["scored_controls"]
        for control_key, after in current_controls.items():
            previous = previous_controls.get(control_key)
            if previous is None:
                if after["status"] in _ACTIONABLE_STATUSES:
                    regressions.append(
                        RouteRegression(
                            route_id=route_id,
                            code="control.new_actionable_finding",
                            severity=after["severity"],
                            control_key=control_key,
                            previous=None,
                            current=after["status"],
                            message=(
                                "A new actionable scored-control finding is not in the "
                                "approved route baseline."
                            ),
                        )
                    )
                continue
            if _status_rank(after["status"]) > _status_rank(previous["status"]):
                regressions.append(
                    RouteRegression(
                        route_id=route_id,
                        code="control.status_regressed",
                        severity=after["severity"],
                        control_key=control_key,
                        previous=previous["status"],
                        current=after["status"],
                        message="Scored-control status is worse than the approved baseline.",
                    )
                )
                continue
            if _severity_rank(after["severity"]) > _severity_rank(previous["severity"]):
                regressions.append(
                    RouteRegression(
                        route_id=route_id,
                        code="control.severity_regressed",
                        severity=after["severity"],
                        control_key=control_key,
                        previous=previous["severity"],
                        current=after["severity"],
                        message="Scored-control severity is worse than the approved baseline.",
                    )
                )
                continue
            if after["points"] < previous["points"]:
                regressions.append(
                    RouteRegression(
                        route_id=route_id,
                        code="control.points_regressed",
                        severity=after["severity"],
                        control_key=control_key,
                        previous=previous["points"],
                        current=after["points"],
                        message=(
                            "Scored-control points decreased from the approved route baseline."
                        ),
                    )
                )
        for control_key in sorted(set(previous_controls) - set(current_controls)):
            regressions.append(
                RouteRegression(
                    route_id=route_id,
                    code="control.missing_from_run",
                    severity="high",
                    control_key=control_key,
                    previous=previous_controls[control_key]["status"],
                    current=None,
                    message=(
                        "An approved scored control is missing from a route run with the same "
                        "methodology version."
                    ),
                )
            )
    return tuple(_deduplicate_route_regressions(regressions))


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


def route_assurance_dict(run: RouteAssuranceRun) -> dict[str, Any]:
    """Return compact, data-minimized route drift evidence for CI and review."""
    payload = route_comparison_dict(run.comparison)
    payload["artifact"] = ROUTE_ASSURANCE_ARTIFACT
    payload["route_assurance"] = {
        "baseline_schema_version": run.baseline_schema_version,
        "outcome": run.outcome,
        "exit_code": run.exit_code,
        "regressions": [
            {
                "route_id": regression.route_id,
                "code": regression.code,
                "severity": regression.severity,
                "control_key": regression.control_key,
                "previous": regression.previous,
                "current": regression.current,
                "message": regression.message,
            }
            for regression in run.regressions
        ],
    }
    return payload


def render_route_assurance_json(run: RouteAssuranceRun) -> str:
    return json.dumps(route_assurance_dict(run), indent=2, sort_keys=True) + "\n"


def route_assurance_review_dict(run: RouteAssuranceRun) -> dict[str, Any]:
    """Return a data-minimized route-assurance artifact for offline review.

    Route paths and origins remain in the separately validated scope artifact.
    This output intentionally carries no raw header data, URLs, or diagnostic
    prose, so it can be bound to that scope in a portable evidence capsule.
    """
    return {
        "schema_version": ROUTE_ASSURANCE_REVIEW_SCHEMA_VERSION,
        "artifact": ROUTE_ASSURANCE_REVIEW_ARTIFACT,
        "methodology_version": METHODOLOGY_VERSION,
        "mapping_set_version": MAPPING_SET_VERSION,
        "manifest_name": run.comparison.config.name,
        "manifest_schema_version": run.comparison.config.schema_version,
        "baseline_schema_version": run.baseline_schema_version,
        "outcome": run.outcome,
        "exit_code": run.exit_code,
        "routes": [
            {
                "route_id": assessment.route.id,
                "selected_profile": assessment.result.selected_profile,
                "score": None if assessment.result.error else assessment.result.score,
                "scored_controls": [
                    {
                        "key": finding.key,
                        "status": finding.status,
                        "severity": finding.severity,
                        "points": finding.points,
                        "max_points": finding.max_points,
                    }
                    for finding in sorted(assessment.result.findings, key=lambda item: item.key)
                    if finding.category == "scored"
                ],
            }
            for assessment in sorted(run.comparison.assessments, key=lambda item: item.route.id)
        ],
        "regressions": [
            {
                "route_id": item.route_id,
                "code": item.code,
                "severity": item.severity,
                "control_key": item.control_key,
            }
            for item in run.regressions
        ],
        "operational_error_count": len(run.comparison.operational_errors),
        "control_variance_count": len(run.comparison.variances),
        "limitations": [
            "This compact review artifact omits route URLs, raw response-header values, response metadata, and diagnostic prose.",
            "It records explicit route-manifest evaluation state for review; it is not a security pass, compliance decision, vulnerability finding, or browser runtime validation.",
        ],
    }


def render_route_assurance_review_json(run: RouteAssuranceRun) -> str:
    return json.dumps(route_assurance_review_dict(run), indent=2, sort_keys=True) + "\n"


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


def render_route_assurance_markdown(run: RouteAssuranceRun) -> str:
    lines = [render_route_comparison_markdown(run.comparison).rstrip(), "", "## Route Assurance", ""]
    lines.extend(
        [
            f"- Outcome: `{run.outcome}`",
            (
                "- Approved baseline: "
                + (f"schema `{run.baseline_schema_version}`" if run.baseline_schema_version else "not supplied")
            ),
        ]
    )
    if run.regressions:
        lines.extend(["", "| Route | Signal | Control | Previous | Current |", "| --- | --- | --- | --- | --- |"])
        for regression in run.regressions:
            lines.append(
                "| "
                f"`{_escape_markdown(regression.route_id)}` | "
                f"`{_escape_markdown(regression.code)}` | "
                f"`{_escape_markdown(regression.control_key or '-')}` | "
                f"`{_escape_markdown(str(regression.previous)) if regression.previous is not None else '-'}` | "
                f"`{_escape_markdown(str(regression.current)) if regression.current is not None else '-'}` |"
            )
    else:
        lines.extend(["", "No route-baseline regression was detected."])
    lines.extend(
        [
            "",
            "A baseline records a reviewed comparison state. It is not a security pass, waiver, compliance decision, or proof of browser behaviour.",
            "",
        ]
    )
    return "\n".join(lines)


def _manifest_dict(config: RouteComparisonConfig) -> dict[str, Any]:
    """Canonical route scope used for baseline compatibility checks."""
    return {
        "schema_version": config.schema_version,
        "name": config.name,
        "origin": config.origin,
        "routes": [
            {
                "id": route.id,
                "path": route.path,
                "profile": route.profile.value,
            }
            for route in sorted(config.routes, key=lambda item: item.id)
        ],
    }


def _baseline_route(assessment: RouteAssessment) -> dict[str, Any]:
    result = assessment.result
    if result.error:
        raise RouteBaselineCompatibilityError(
            f"Route {assessment.route.id!r} cannot enter a baseline after an audit error."
        )
    return {
        "path": assessment.route.path,
        "declared_profile": assessment.route.profile.value,
        "score": result.score,
        "scored_controls": {
            finding.key: {
                "status": finding.status,
                "severity": finding.severity,
                "points": finding.points,
                "max_points": finding.max_points,
            }
            for finding in sorted(result.findings, key=lambda item: item.key)
            if finding.category == "scored"
        },
    }


def _validate_baseline_route(
    route_id: str,
    payload: Any,
    definition: RouteDefinition,
) -> None:
    if not isinstance(payload, dict):
        raise RouteBaselineCompatibilityError(
            f"Route baseline entry {route_id!r} must be a JSON object."
        )
    _reject_baseline_unknown_keys(
        payload,
        {"path", "declared_profile", "score", "scored_controls"},
        f"route baseline entry {route_id!r}",
    )
    if payload.get("path") != definition.path:
        raise RouteBaselineCompatibilityError(
            f"Route baseline entry {route_id!r} does not match its manifest path."
        )
    if payload.get("declared_profile") != definition.profile.value:
        raise RouteBaselineCompatibilityError(
            f"Route baseline entry {route_id!r} does not match its declared profile."
        )
    score = payload.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        raise RouteBaselineCompatibilityError(
            f"Route baseline entry {route_id!r} has an invalid score."
        )
    controls = payload.get("scored_controls")
    if not isinstance(controls, dict) or not controls:
        raise RouteBaselineCompatibilityError(
            f"Route baseline entry {route_id!r} requires scored controls."
        )
    for control_key, control in controls.items():
        if not isinstance(control_key, str) or not control_key:
            raise RouteBaselineCompatibilityError(
                f"Route baseline entry {route_id!r} has an invalid control key."
            )
        if not isinstance(control, dict):
            raise RouteBaselineCompatibilityError(
                f"Route baseline control {route_id!r}/{control_key!r} must be a JSON object."
            )
        _reject_baseline_unknown_keys(
            control,
            {"status", "severity", "points", "max_points"},
            f"route baseline control {route_id!r}/{control_key!r}",
        )
        if control.get("status") not in _BASELINE_STATUSES:
            raise RouteBaselineCompatibilityError(
                f"Route baseline control {route_id!r}/{control_key!r} has an invalid status."
            )
        if control.get("severity") not in _BASELINE_SEVERITIES:
            raise RouteBaselineCompatibilityError(
                f"Route baseline control {route_id!r}/{control_key!r} has an invalid severity."
            )
        for field in ("points", "max_points"):
            value = control.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise RouteBaselineCompatibilityError(
                    f"Route baseline control {route_id!r}/{control_key!r} has an invalid {field}."
                )
        if control["points"] > control["max_points"]:
            raise RouteBaselineCompatibilityError(
                f"Route baseline control {route_id!r}/{control_key!r} has points above max_points."
            )


def _require_baseline_value(
    payload: dict[str, Any],
    field: str,
    expected: str,
    context: str,
) -> None:
    if payload.get(field) != expected:
        raise RouteBaselineCompatibilityError(
            f"{context.capitalize()} {field} {payload.get(field)!r} is incompatible with {expected!r}."
        )


def _reject_baseline_unknown_keys(
    payload: dict[str, Any],
    allowed: set[str],
    context: str,
) -> None:
    unknown = set(payload) - allowed
    if unknown:
        raise RouteBaselineCompatibilityError(
            f"Unknown {context} field(s): {', '.join(sorted(unknown))}."
        )


def _status_rank(status: str) -> int:
    return {
        "pass": 0,
        "info": 0,
        "observed": 0,
        "not_applicable": 0,
        "review": 1,
        "warning": 2,
        "missing": 3,
        "error": 4,
    }.get(status, 2)


def _severity_rank(severity: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3}.get(severity, 2)


def _deduplicate_route_regressions(
    regressions: list[RouteRegression],
) -> list[RouteRegression]:
    unique: dict[tuple[str, str, str | None], RouteRegression] = {}
    for regression in regressions:
        key = (regression.route_id, regression.code, regression.control_key)
        unique.setdefault(key, regression)
    return list(unique.values())


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
