"""Policy-as-code execution and deterministic baseline regression analysis."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

from . import METHODOLOGY_VERSION
from .assurance_controls import AssuranceExpectation, parse_expectation
from .auditor import AuditResult, audit_headers
from .catalog import DISCLOSURE_HEADERS, RULES_BY_KEY
from .compliance import MAPPING_SET_VERSION
from .profiles import parse_profile


POLICY_SCHEMA_VERSION = "1.0"
BASELINE_SCHEMA_VERSION = "1.0"
ASSURANCE_CONTROL_KEYS = {
    "reporting-endpoints",
    "reporting-readiness",
    "cross-origin-isolation-bundle",
}
KNOWN_CONTROL_KEYS = set(RULES_BY_KEY) | ASSURANCE_CONTROL_KEYS
BASELINE_CONTROL_KEYS = KNOWN_CONTROL_KEYS | set(DISCLOSURE_HEADERS)
ACTIONABLE_STATUSES = {"missing", "warning", "review"}
SEVERITIES = {"high", "medium", "low"}
BASELINE_STATUSES = {
    "pass",
    "info",
    "observed",
    "not_applicable",
    "review",
    "warning",
    "missing",
    "error",
}
BASELINE_SEVERITIES = SEVERITIES | {"info"}
BASELINE_CATEGORIES = {"scored", "contextual", "assurance", "disclosure"}
BASELINE_APPLICABILITIES = {
    "required",
    "recommended",
    "informational",
    "observe",
    "not_applicable",
}


class PolicyConfigurationError(ValueError):
    """Raised when an assurance policy cannot be interpreted safely."""


class BaselineCompatibilityError(ValueError):
    """Raised when a baseline was produced by an incompatible methodology."""


@dataclass(frozen=True)
class PolicyDefaults:
    profile: str = "auto"
    minimum_score: int = 0
    maximum_score_drop: int = 0
    fail_on_severity: tuple[str, ...] = ("high",)
    required_controls: tuple[str, ...] = ()
    reporting_readiness: str = AssuranceExpectation.OBSERVE.value
    cross_origin_isolation: str = AssuranceExpectation.OBSERVE.value
    allow_cross_origin_redirects: bool = False
    include_query: bool = False
    timeout: float = 8.0
    allow_auto_profile: bool = False


@dataclass(frozen=True)
class TargetPolicy:
    id: str
    url: str
    profile: str
    minimum_score: int
    maximum_score_drop: int
    fail_on_severity: tuple[str, ...]
    required_controls: tuple[str, ...]
    reporting_readiness: str
    cross_origin_isolation: str
    allow_cross_origin_redirects: bool
    include_query: bool
    timeout: float


@dataclass(frozen=True)
class AssurancePolicy:
    schema_version: str
    methodology_version: str
    name: str
    defaults: PolicyDefaults
    targets: tuple[TargetPolicy, ...]


@dataclass(frozen=True)
class TargetAssessment:
    target_id: str
    policy: TargetPolicy
    result: AuditResult


@dataclass(frozen=True)
class PolicyViolation:
    target_id: str
    code: str
    severity: str
    control_key: str | None
    message: str


@dataclass(frozen=True)
class Regression:
    target_id: str
    code: str
    severity: str
    control_key: str | None
    previous: str | int | float | None
    current: str | int | float | None
    message: str


@dataclass(frozen=True)
class AssuranceRun:
    methodology_version: str
    mapping_set_version: str
    policy_name: str
    policy_schema_version: str
    baseline_schema_version: str | None
    assessments: tuple[TargetAssessment, ...]
    policy_violations: tuple[PolicyViolation, ...]
    regressions: tuple[Regression, ...]
    operational_errors: tuple[str, ...]

    @property
    def outcome(self) -> str:
        if self.operational_errors:
            return "operational_error"
        if self.policy_violations or self.regressions:
            return "failed"
        return "passed"

    @property
    def exit_code(self) -> int:
        if self.operational_errors:
            return 2
        if self.policy_violations or self.regressions:
            return 1
        return 0


AuditFunction = Callable[..., AuditResult]


def load_policy(path: Path) -> AssurancePolicy:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyConfigurationError(f"Cannot read policy {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PolicyConfigurationError(
            f"Policy {path} is not valid JSON: line {exc.lineno}, column {exc.colno}."
        ) from exc
    return parse_policy(payload)


def parse_policy(payload: dict[str, Any]) -> AssurancePolicy:
    if not isinstance(payload, dict):
        raise PolicyConfigurationError("Policy root must be a JSON object.")
    _reject_unknown_keys(
        payload,
        {"schema_version", "methodology_version", "name", "defaults", "targets"},
        "policy",
    )
    schema_version = _required_string(payload, "schema_version", "policy")
    if schema_version != POLICY_SCHEMA_VERSION:
        raise PolicyConfigurationError(
            f"Unsupported policy schema {schema_version}; expected {POLICY_SCHEMA_VERSION}."
        )
    methodology_version = _required_string(payload, "methodology_version", "policy")
    if methodology_version != METHODOLOGY_VERSION:
        raise PolicyConfigurationError(
            "Policy methodology "
            f"{methodology_version} does not match {METHODOLOGY_VERSION}."
        )
    name = _required_string(payload, "name", "policy")
    defaults_payload = payload.get("defaults", {})
    if not isinstance(defaults_payload, dict):
        raise PolicyConfigurationError("Policy defaults must be a JSON object.")
    defaults = _parse_defaults(defaults_payload)

    targets_payload = payload.get("targets")
    if not isinstance(targets_payload, list) or not targets_payload:
        raise PolicyConfigurationError("Policy targets must be a non-empty JSON array.")
    targets = tuple(_parse_target(item, defaults) for item in targets_payload)
    ids = [target.id for target in targets]
    if len(set(ids)) != len(ids):
        raise PolicyConfigurationError("Every policy target id must be unique.")
    return AssurancePolicy(
        schema_version=schema_version,
        methodology_version=methodology_version,
        name=name,
        defaults=defaults,
        targets=targets,
    )


def run_assurance(
    policy: AssurancePolicy,
    baseline: dict[str, Any] | None = None,
    audit_function: AuditFunction = audit_headers,
) -> AssuranceRun:
    assessments: list[TargetAssessment] = []
    violations: list[PolicyViolation] = []
    operational_errors: list[str] = []

    for target_policy in policy.targets:
        result = audit_function(
            target_policy.url,
            timeout=target_policy.timeout,
            profile=target_policy.profile,
            include_query=target_policy.include_query,
            allow_cross_origin_redirects=target_policy.allow_cross_origin_redirects,
            reporting_expectation=target_policy.reporting_readiness,
            cross_origin_isolation=target_policy.cross_origin_isolation,
        )
        assessment = TargetAssessment(
            target_id=target_policy.id,
            policy=target_policy,
            result=result,
        )
        assessments.append(assessment)
        if result.error:
            operational_errors.append(
                f"{target_policy.id}: audit failed: {result.error}"
            )
            continue
        violations.extend(_evaluate_target_policy(assessment))

    regressions: tuple[Regression, ...] = ()
    baseline_schema_version: str | None = None
    if baseline is not None:
        try:
            baseline_schema_version = validate_baseline(baseline)
            if baseline.get("policy_name") != policy.name:
                raise BaselineCompatibilityError(
                    f"Baseline policy {baseline.get('policy_name')!r} does not match "
                    f"{policy.name!r}."
                )
            regressions = compare_baseline(tuple(assessments), baseline)
        except BaselineCompatibilityError as exc:
            operational_errors.append(str(exc))

    return AssuranceRun(
        methodology_version=METHODOLOGY_VERSION,
        mapping_set_version=MAPPING_SET_VERSION,
        policy_name=policy.name,
        policy_schema_version=policy.schema_version,
        baseline_schema_version=baseline_schema_version,
        assessments=tuple(assessments),
        policy_violations=tuple(violations),
        regressions=regressions,
        operational_errors=tuple(operational_errors),
    )


def create_baseline(run: AssuranceRun) -> dict[str, Any]:
    if run.exit_code != 0:
        raise BaselineCompatibilityError(
            "A baseline can be created only from a passing assurance run with no "
            "policy violations, regressions, or operational errors."
        )
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "methodology_version": run.methodology_version,
        "mapping_set_version": run.mapping_set_version,
        "policy_name": run.policy_name,
        "targets": {
            assessment.target_id: _baseline_target(assessment)
            for assessment in sorted(
                run.assessments,
                key=lambda item: item.target_id,
            )
        },
    }


def write_baseline(path: Path, run: AssuranceRun) -> None:
    payload = create_baseline(run)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineCompatibilityError(f"Cannot read baseline {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineCompatibilityError(
            f"Baseline {path} is not valid JSON: line {exc.lineno}, column {exc.colno}."
        ) from exc
    validate_baseline(payload)
    return payload


def validate_baseline(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        raise BaselineCompatibilityError("Baseline root must be a JSON object.")
    schema_version = payload.get("schema_version")
    if schema_version != BASELINE_SCHEMA_VERSION:
        raise BaselineCompatibilityError(
            f"Baseline schema {schema_version!r} is incompatible with "
            f"{BASELINE_SCHEMA_VERSION}."
        )
    methodology = payload.get("methodology_version")
    if methodology != METHODOLOGY_VERSION:
        raise BaselineCompatibilityError(
            "Baseline methodology "
            f"{methodology!r} does not match {METHODOLOGY_VERSION}; "
            "review the methodology change and create a new approved baseline."
        )
    mapping_version = payload.get("mapping_set_version")
    if mapping_version != MAPPING_SET_VERSION:
        raise BaselineCompatibilityError(
            f"Baseline mapping set {mapping_version!r} does not match "
            f"{MAPPING_SET_VERSION}; review the evidence changes before re-baselining."
        )
    if not isinstance(payload.get("targets"), dict):
        raise BaselineCompatibilityError("Baseline targets must be a JSON object.")
    if not isinstance(payload.get("policy_name"), str) or not payload["policy_name"]:
        raise BaselineCompatibilityError("Baseline policy_name must be non-empty.")
    allowed_root = {
        "schema_version",
        "methodology_version",
        "mapping_set_version",
        "policy_name",
        "targets",
    }
    unknown_root = set(payload) - allowed_root
    if unknown_root:
        raise BaselineCompatibilityError(
            "Unknown baseline fields: " + ", ".join(sorted(unknown_root))
        )
    for target_id, target in payload["targets"].items():
        if not isinstance(target_id, str) or not target_id:
            raise BaselineCompatibilityError("Baseline target ids must be non-empty.")
        if not isinstance(target, dict):
            raise BaselineCompatibilityError(
                f"Baseline target {target_id!r} must be a JSON object."
            )
        required_target = {"target", "selected_profile", "score", "findings"}
        if set(target) != required_target:
            raise BaselineCompatibilityError(
                f"Baseline target {target_id!r} has invalid fields."
            )
        if not isinstance(target["target"], str) or not target["target"]:
            raise BaselineCompatibilityError(
                f"Baseline target URL for {target_id!r} must be a non-empty string."
            )
        if target["selected_profile"] not in {"app", "api", "brochure"}:
            raise BaselineCompatibilityError(
                f"Baseline profile for {target_id!r} is invalid."
            )
        if (
            isinstance(target["score"], bool)
            or not isinstance(target["score"], int)
            or not 0 <= target["score"] <= 100
        ):
            raise BaselineCompatibilityError(
                f"Baseline score for {target_id!r} is invalid."
            )
        if not isinstance(target["findings"], dict):
            raise BaselineCompatibilityError(
                f"Baseline findings for {target_id!r} must be a JSON object."
            )
        for control_key, finding in target["findings"].items():
            _validate_baseline_finding(target_id, control_key, finding)
    return schema_version


def _validate_baseline_finding(
    target_id: str,
    control_key: str,
    finding: Any,
) -> None:
    if not isinstance(control_key, str) or not control_key:
        raise BaselineCompatibilityError(
            f"Baseline {target_id!r} contains an invalid control key."
        )
    if control_key not in BASELINE_CONTROL_KEYS:
        raise BaselineCompatibilityError(
            f"Baseline {target_id!r} contains unknown control {control_key!r}."
        )
    if not isinstance(finding, dict):
        raise BaselineCompatibilityError(
            f"Baseline finding {target_id!r}/{control_key!r} must be an object."
        )
    required = {
        "status",
        "severity",
        "category",
        "applicability",
        "points",
        "max_points",
    }
    if set(finding) != required:
        raise BaselineCompatibilityError(
            f"Baseline finding {target_id!r}/{control_key!r} has invalid fields."
        )
    for field in ("status", "severity", "category", "applicability"):
        if not isinstance(finding[field], str):
            raise BaselineCompatibilityError(
                f"Baseline finding {target_id!r}/{control_key!r} has invalid {field}."
            )
    allowed_values = {
        "status": BASELINE_STATUSES,
        "severity": BASELINE_SEVERITIES,
        "category": BASELINE_CATEGORIES,
        "applicability": BASELINE_APPLICABILITIES,
    }
    for field, allowed in allowed_values.items():
        if finding[field] not in allowed:
            raise BaselineCompatibilityError(
                f"Baseline finding {target_id!r}/{control_key!r} has unknown {field}."
            )
    for field in ("points", "max_points"):
        if (
            isinstance(finding[field], bool)
            or not isinstance(finding[field], (int, float))
            or finding[field] < 0
        ):
            raise BaselineCompatibilityError(
                f"Baseline finding {target_id!r}/{control_key!r} has invalid {field}."
            )
    if finding["points"] > finding["max_points"]:
        raise BaselineCompatibilityError(
            f"Baseline finding {target_id!r}/{control_key!r} has points above max_points."
        )


def compare_baseline(
    assessments: tuple[TargetAssessment, ...],
    baseline: dict[str, Any],
) -> tuple[Regression, ...]:
    validate_baseline(baseline)
    baseline_targets = baseline["targets"]
    regressions: list[Regression] = []
    current_ids = {assessment.target_id for assessment in assessments}
    for orphaned_id in sorted(set(baseline_targets) - current_ids):
        regressions.append(
            Regression(
                target_id=orphaned_id,
                code="baseline.orphaned_target",
                severity="high",
                control_key=None,
                previous="present",
                current="absent",
                message=(
                    "An approved baseline target is absent from the current policy; "
                    "review target removal and explicitly re-baseline."
                ),
            )
        )

    for assessment in assessments:
        if assessment.result.error:
            continue
        previous = baseline_targets.get(assessment.target_id)
        if not isinstance(previous, dict):
            regressions.append(
                Regression(
                    target_id=assessment.target_id,
                    code="baseline.unapproved_target",
                    severity="high",
                    control_key=None,
                    previous=None,
                    current=assessment.result.score,
                    message=(
                        "Target is not present in the approved baseline; review and "
                        "explicitly re-baseline before accepting it in CI."
                    ),
                )
            )
            continue

        previous_target = previous.get("target")
        if previous_target != assessment.result.target:
            regressions.append(
                Regression(
                    target_id=assessment.target_id,
                    code="target.changed",
                    severity="high",
                    control_key=None,
                    previous=previous_target,
                    current=assessment.result.target,
                    message="The URL associated with the stable target id changed.",
                )
            )

        previous_profile = previous.get("selected_profile")
        if previous_profile != assessment.result.selected_profile:
            regressions.append(
                Regression(
                    target_id=assessment.target_id,
                    code="profile.changed",
                    severity="high",
                    control_key=None,
                    previous=previous_profile,
                    current=assessment.result.selected_profile,
                    message="Selected response profile changed from the approved baseline.",
                )
            )

        previous_score = previous.get("score")
        if isinstance(previous_score, int):
            drop = previous_score - assessment.result.score
            if drop > assessment.policy.maximum_score_drop:
                regressions.append(
                    Regression(
                        target_id=assessment.target_id,
                        code="score.regressed",
                        severity="high",
                        control_key=None,
                        previous=previous_score,
                        current=assessment.result.score,
                        message=(
                            f"Score decreased by {drop} point(s); allowed decrease is "
                            f"{assessment.policy.maximum_score_drop}."
                        ),
                    )
                )

        previous_findings = previous.get("findings", {})
        current_findings = {
            finding.key: finding for finding in assessment.result.findings
        }
        if not isinstance(previous_findings, dict):
            raise BaselineCompatibilityError(
                f"Baseline findings for {assessment.target_id!r} are invalid."
            )
        for control_key, current in current_findings.items():
            before = previous_findings.get(control_key)
            if not isinstance(before, dict):
                if current.status in ACTIONABLE_STATUSES:
                    regressions.append(
                        Regression(
                            target_id=assessment.target_id,
                            code="control.new_actionable_finding",
                            severity=current.severity,
                            control_key=control_key,
                            previous=None,
                            current=current.status,
                            message="A new actionable control finding is not in the baseline.",
                        )
                    )
                continue
            previous_status = before.get("status")
            status_regressed = _status_rank(current.status) > _status_rank(
                str(previous_status)
            )
            if status_regressed:
                regressions.append(
                    Regression(
                        target_id=assessment.target_id,
                        code="control.status_regressed",
                        severity=current.severity,
                        control_key=control_key,
                        previous=str(previous_status),
                        current=current.status,
                        message="Control status is worse than the approved baseline.",
                    )
                )
                continue
            previous_severity = str(before.get("severity"))
            if _severity_rank(current.severity) > _severity_rank(previous_severity):
                regressions.append(
                    Regression(
                        target_id=assessment.target_id,
                        code="control.severity_regressed",
                        severity=current.severity,
                        control_key=control_key,
                        previous=previous_severity,
                        current=current.severity,
                        message="Control severity is worse than the approved baseline.",
                    )
                )
                continue
            previous_points = before.get("points")
            if (
                isinstance(previous_points, (int, float))
                and not isinstance(previous_points, bool)
                and current.points < previous_points
            ):
                regressions.append(
                    Regression(
                        target_id=assessment.target_id,
                        code="control.points_regressed",
                        severity=current.severity,
                        control_key=control_key,
                        previous=previous_points,
                        current=current.points,
                        message="Control points decreased from the approved baseline.",
                    )
                )

        for removed_key in sorted(set(previous_findings) - set(current_findings)):
            regressions.append(
                Regression(
                    target_id=assessment.target_id,
                    code="control.missing_from_run",
                    severity="high",
                    control_key=removed_key,
                    previous=str(previous_findings[removed_key].get("status")),
                    current=None,
                    message=(
                        "A baseline control is missing from a run with the same "
                        "methodology version."
                    ),
                )
            )

    return tuple(_deduplicate_regressions(regressions))


def assurance_run_dict(run: AssuranceRun) -> dict[str, Any]:
    return {
        "methodology_version": run.methodology_version,
        "mapping_set_version": run.mapping_set_version,
        "policy_name": run.policy_name,
        "policy_schema_version": run.policy_schema_version,
        "baseline_schema_version": run.baseline_schema_version,
        "outcome": run.outcome,
        "exit_code": run.exit_code,
        "assessments": [
            {
                "target_id": assessment.target_id,
                "policy": asdict(assessment.policy),
                "result": asdict(assessment.result),
            }
            for assessment in run.assessments
        ],
        "policy_violations": [asdict(item) for item in run.policy_violations],
        "regressions": [asdict(item) for item in run.regressions],
        "operational_errors": list(run.operational_errors),
    }


def _evaluate_target_policy(
    assessment: TargetAssessment,
) -> tuple[PolicyViolation, ...]:
    result = assessment.result
    policy = assessment.policy
    violations: list[PolicyViolation] = []
    if result.score < policy.minimum_score:
        violations.append(
            PolicyViolation(
                target_id=assessment.target_id,
                code="score.below_minimum",
                severity="high",
                control_key=None,
                message=(
                    f"Score {result.score} is below the policy minimum "
                    f"{policy.minimum_score}."
                ),
            )
        )

    findings = {finding.key: finding for finding in result.findings}
    for control_key in policy.required_controls:
        finding = findings.get(control_key)
        if finding is None or finding.status != "pass":
            status = finding.status if finding else "not_evaluated"
            violations.append(
                PolicyViolation(
                    target_id=assessment.target_id,
                    code="control.required_not_passed",
                    severity="high",
                    control_key=control_key,
                    message=f"Required control did not pass; current status is {status}.",
                )
            )

    required_assurance = {
        "reporting-readiness": policy.reporting_readiness,
        "cross-origin-isolation-bundle": policy.cross_origin_isolation,
    }
    for control_key, expectation in required_assurance.items():
        if expectation != AssuranceExpectation.REQUIRED.value:
            continue
        finding = findings.get(control_key)
        if finding is None or finding.status != "pass":
            violations.append(
                PolicyViolation(
                    target_id=assessment.target_id,
                    code="assurance.required_not_ready",
                    severity="high",
                    control_key=control_key,
                    message=(
                        f"Required assurance capability did not pass; current status is "
                        f"{finding.status if finding else 'not_evaluated'}."
                    ),
                )
            )

    for finding in result.findings:
        if (
            finding.status in ACTIONABLE_STATUSES
            and finding.severity in policy.fail_on_severity
        ):
            violations.append(
                PolicyViolation(
                    target_id=assessment.target_id,
                    code="finding.disallowed_severity",
                    severity=finding.severity,
                    control_key=finding.key,
                    message=(
                        f"{finding.name} is {finding.status} with "
                        f"{finding.severity} severity."
                    ),
                )
            )
    return tuple(_deduplicate_violations(violations))


def _baseline_target(assessment: TargetAssessment) -> dict[str, Any]:
    result = assessment.result
    return {
        "target": result.target,
        "selected_profile": result.selected_profile,
        "score": result.score,
        "findings": {
            finding.key: {
                "status": finding.status,
                "severity": finding.severity,
                "category": finding.category,
                "applicability": finding.applicability,
                "points": finding.points,
                "max_points": finding.max_points,
            }
            for finding in sorted(result.findings, key=lambda item: item.key)
        },
    }


def _parse_defaults(payload: dict[str, Any]) -> PolicyDefaults:
    allowed = {
        "profile",
        "minimum_score",
        "maximum_score_drop",
        "fail_on_severity",
        "required_controls",
        "reporting_readiness",
        "cross_origin_isolation",
        "allow_cross_origin_redirects",
        "include_query",
        "timeout",
        "allow_auto_profile",
    }
    _reject_unknown_keys(payload, allowed, "policy defaults")
    defaults = PolicyDefaults(
        profile=parse_profile(str(payload.get("profile", "auto"))),
        minimum_score=_bounded_int(payload.get("minimum_score", 0), "minimum_score"),
        maximum_score_drop=_bounded_int(
            payload.get("maximum_score_drop", 0),
            "maximum_score_drop",
        ),
        fail_on_severity=_parse_severities(
            payload.get("fail_on_severity", ["high"])
        ),
        required_controls=_parse_control_keys(
            payload.get("required_controls", [])
        ),
        reporting_readiness=parse_expectation(
            str(payload.get("reporting_readiness", "observe"))
        ).value,
        cross_origin_isolation=parse_expectation(
            str(payload.get("cross_origin_isolation", "observe"))
        ).value,
        allow_cross_origin_redirects=_boolean(
            payload.get("allow_cross_origin_redirects", False),
            "allow_cross_origin_redirects",
        ),
        include_query=_boolean(payload.get("include_query", False), "include_query"),
        timeout=_positive_number(payload.get("timeout", 8.0), "timeout"),
        allow_auto_profile=_boolean(
            payload.get("allow_auto_profile", False),
            "allow_auto_profile",
        ),
    )
    if defaults.profile == "auto" and not defaults.allow_auto_profile:
        return defaults
    return defaults


def _parse_target(payload: Any, defaults: PolicyDefaults) -> TargetPolicy:
    if not isinstance(payload, dict):
        raise PolicyConfigurationError("Each policy target must be a JSON object.")
    allowed = {
        "id",
        "url",
        "profile",
        "minimum_score",
        "maximum_score_drop",
        "fail_on_severity",
        "required_controls",
        "reporting_readiness",
        "cross_origin_isolation",
        "allow_cross_origin_redirects",
        "include_query",
        "timeout",
    }
    _reject_unknown_keys(payload, allowed, "policy target")
    target_id = _required_string(payload, "id", "policy target")
    url = _required_string(payload, "url", f"target {target_id}")
    profile = parse_profile(str(payload.get("profile", defaults.profile)))
    if profile == "auto" and not defaults.allow_auto_profile:
        raise PolicyConfigurationError(
            f"Target {target_id!r} uses auto profile. Continuous assurance requires "
            "an explicit profile unless defaults.allow_auto_profile is true."
        )
    return TargetPolicy(
        id=target_id,
        url=url,
        profile=profile,
        minimum_score=_bounded_int(
            payload.get("minimum_score", defaults.minimum_score),
            f"{target_id}.minimum_score",
        ),
        maximum_score_drop=_bounded_int(
            payload.get("maximum_score_drop", defaults.maximum_score_drop),
            f"{target_id}.maximum_score_drop",
        ),
        fail_on_severity=_parse_severities(
            payload.get("fail_on_severity", list(defaults.fail_on_severity))
        ),
        required_controls=_parse_control_keys(
            payload.get("required_controls", list(defaults.required_controls))
        ),
        reporting_readiness=parse_expectation(
            str(payload.get("reporting_readiness", defaults.reporting_readiness))
        ).value,
        cross_origin_isolation=parse_expectation(
            str(
                payload.get(
                    "cross_origin_isolation",
                    defaults.cross_origin_isolation,
                )
            )
        ).value,
        allow_cross_origin_redirects=_boolean(
            payload.get(
                "allow_cross_origin_redirects",
                defaults.allow_cross_origin_redirects,
            ),
            f"{target_id}.allow_cross_origin_redirects",
        ),
        include_query=_boolean(
            payload.get("include_query", defaults.include_query),
            f"{target_id}.include_query",
        ),
        timeout=_positive_number(
            payload.get("timeout", defaults.timeout),
            f"{target_id}.timeout",
        ),
    )


def _parse_severities(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyConfigurationError("fail_on_severity must be a JSON array.")
    parsed = tuple(str(item).lower() for item in value)
    unknown = set(parsed) - SEVERITIES
    if unknown:
        raise PolicyConfigurationError(
            "Unknown fail_on_severity values: " + ", ".join(sorted(unknown))
        )
    if len(set(parsed)) != len(parsed):
        raise PolicyConfigurationError("fail_on_severity values must be unique.")
    return parsed


def _parse_control_keys(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyConfigurationError("required_controls must be a JSON array.")
    parsed = tuple(str(item) for item in value)
    unknown = set(parsed) - KNOWN_CONTROL_KEYS
    if unknown:
        raise PolicyConfigurationError(
            "Unknown required control keys: " + ", ".join(sorted(unknown))
        )
    if len(set(parsed)) != len(parsed):
        raise PolicyConfigurationError("required_controls values must be unique.")
    return parsed


def _required_string(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PolicyConfigurationError(f"{context} requires non-empty {key}.")
    return value.strip()


def _bounded_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise PolicyConfigurationError(f"{field} must be an integer from 0 to 100.")
    return value


def _positive_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise PolicyConfigurationError(f"{field} must be a positive number.")
    return float(value)


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyConfigurationError(f"{field} must be true or false.")
    return value


def _reject_unknown_keys(
    payload: dict[str, Any],
    allowed: set[str],
    context: str,
) -> None:
    unknown = set(payload) - allowed
    if unknown:
        raise PolicyConfigurationError(
            f"Unknown {context} fields: " + ", ".join(sorted(unknown))
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


def _deduplicate_violations(
    violations: list[PolicyViolation],
) -> list[PolicyViolation]:
    unique: dict[tuple[str, str, str | None], PolicyViolation] = {}
    for violation in violations:
        key = (violation.target_id, violation.code, violation.control_key)
        unique.setdefault(key, violation)
    return list(unique.values())


def _deduplicate_regressions(regressions: list[Regression]) -> list[Regression]:
    unique: dict[tuple[str, str, str | None], Regression] = {}
    for regression in regressions:
        key = (regression.target_id, regression.code, regression.control_key)
        unique.setdefault(key, regression)
    return list(unique.values())
