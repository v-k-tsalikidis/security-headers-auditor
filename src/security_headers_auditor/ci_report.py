"""Machine-readable assurance outputs for CI systems."""

from __future__ import annotations

import json
from xml.etree.ElementTree import Element, SubElement, tostring

from .assurance import (
    AssuranceRun,
    PolicyViolation,
    Regression,
    assurance_run_dict,
)


SARIF_VERSION = "2.1.0"


def render_assurance_json(run: AssuranceRun) -> str:
    return json.dumps(assurance_run_dict(run), indent=2, sort_keys=True) + "\n"


def render_sarif(run: AssuranceRun) -> str:
    """Render policy failures and regressions as deterministic SARIF 2.1.0."""
    diagnostics = [
        *_violation_diagnostics(run.policy_violations),
        *_regression_diagnostics(run.regressions),
        *(
            {
                "rule_id": "operational.audit_error",
                "level": "error",
                "message": message,
                "target_id": None,
                "control_key": None,
                "kind": "operational_error",
            }
            for message in run.operational_errors
        ),
    ]
    rule_ids = sorted({item["rule_id"] for item in diagnostics})
    rules = [
        {
            "id": rule_id,
            "name": rule_id.replace(".", "_"),
            "shortDescription": {"text": _rule_description(rule_id)},
            "properties": {
                "methodologyVersion": run.methodology_version,
                "mappingSetVersion": run.mapping_set_version,
            },
        }
        for rule_id in rule_ids
    ]
    results = [
        {
            "ruleId": item["rule_id"],
            "level": item["level"],
            "message": {"text": item["message"]},
            "properties": {
                "targetId": item["target_id"],
                "controlKey": item["control_key"],
                "diagnosticKind": item["kind"],
            },
        }
        for item in diagnostics
    ]
    payload = {
        "$schema": (
            "https://json.schemastore.org/sarif-2.1.0.json"
        ),
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Security Headers Auditor",
                        "semanticVersion": run.methodology_version,
                        "informationUri": (
                            "https://github.com/v-k-tsalikidis/"
                            "security-headers-auditor"
                        ),
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"assurance/{run.policy_name}"},
                "results": results,
                "properties": {
                    "outcome": run.outcome,
                    "policySchemaVersion": run.policy_schema_version,
                    "baselineSchemaVersion": run.baseline_schema_version,
                    "mappingSetVersion": run.mapping_set_version,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_junit(run: AssuranceRun) -> str:
    """Render one deterministic JUnit testcase per policy target."""
    failures_by_target: dict[str, list[str]] = {}
    for violation in run.policy_violations:
        failures_by_target.setdefault(violation.target_id, []).append(
            _format_violation(violation)
        )
    for regression in run.regressions:
        failures_by_target.setdefault(regression.target_id, []).append(
            _format_regression(regression)
        )
    errors_by_target: dict[str, list[str]] = {}
    for message in run.operational_errors:
        target_id, separator, detail = message.partition(":")
        errors_by_target.setdefault(
            target_id if separator else "assurance-run",
            [],
        ).append(detail.strip() if separator else message)

    assessments_by_id = {
        assessment.target_id: assessment
        for assessment in run.assessments
    }
    case_ids = sorted(
        set(assessments_by_id)
        | set(failures_by_target)
        | set(errors_by_target)
    )
    test_count = len(case_ids)
    root = Element(
        "testsuite",
        {
            "name": f"security-headers-assurance:{run.policy_name}",
            "tests": str(test_count),
            "failures": str(sum(bool(items) for items in failures_by_target.values())),
            "errors": str(sum(bool(items) for items in errors_by_target.values())),
            "skipped": "0",
        },
    )
    properties = SubElement(root, "properties")
    for name, value in (
        ("methodology_version", run.methodology_version),
        ("mapping_set_version", run.mapping_set_version),
        ("policy_schema_version", run.policy_schema_version),
        ("outcome", run.outcome),
    ):
        SubElement(properties, "property", {"name": name, "value": value})

    for target_id in case_ids:
        assessment = assessments_by_id.get(target_id)
        case = SubElement(
            root,
            "testcase",
            {
                "classname": "security_headers_auditor.assurance",
                "name": target_id,
            },
        )
        errors = errors_by_target.get(target_id, [])
        failures = failures_by_target.get(target_id, [])
        if errors:
            error = SubElement(
                case,
                "error",
                {
                    "type": "operational_error",
                    "message": "Audit execution failed",
                },
            )
            error.text = "\n".join(errors)
        if failures:
            failure = SubElement(
                case,
                "failure",
                {
                    "type": "assurance_failure",
                    "message": "Policy violation or regression detected",
                },
            )
            failure.text = "\n".join(failures)
        output = SubElement(case, "system-out")
        if assessment is None:
            output.text = (
                "No current assessment exists for this baseline-only or "
                "run-level diagnostic target."
            )
        else:
            output.text = (
                f"score={assessment.result.score}; "
                f"profile={assessment.result.selected_profile}; "
                f"summary={assessment.result.summary}"
            )

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        + tostring(root, encoding="unicode", short_empty_elements=True)
        + "\n"
    )


def _violation_diagnostics(
    violations: tuple[PolicyViolation, ...],
) -> list[dict[str, str | None]]:
    return [
        {
            "rule_id": f"policy.{item.code}",
            "level": _sarif_level(item.severity),
            "message": item.message,
            "target_id": item.target_id,
            "control_key": item.control_key,
            "kind": "policy_violation",
        }
        for item in violations
    ]


def _regression_diagnostics(
    regressions: tuple[Regression, ...],
) -> list[dict[str, str | None]]:
    return [
        {
            "rule_id": f"regression.{item.code}",
            "level": _sarif_level(item.severity),
            "message": (
                f"{item.message} Previous={item.previous!r}; current={item.current!r}."
            ),
            "target_id": item.target_id,
            "control_key": item.control_key,
            "kind": "regression",
        }
        for item in regressions
    ]


def _sarif_level(severity: str) -> str:
    return {"high": "error", "medium": "warning", "low": "note"}.get(
        severity,
        "warning",
    )


def _format_violation(violation: PolicyViolation) -> str:
    control = (
        f"; control={violation.control_key}"
        if violation.control_key
        else ""
    )
    return (
        f"{violation.code}: target={violation.target_id}{control}; "
        f"{violation.message}"
    )


def _format_regression(regression: Regression) -> str:
    control = (
        f"; control={regression.control_key}"
        if regression.control_key
        else ""
    )
    return (
        f"{regression.code}: target={regression.target_id}{control}; "
        f"previous={regression.previous!r}; current={regression.current!r}; "
        f"{regression.message}"
    )


def _rule_description(rule_id: str) -> str:
    return {
        "policy.score.below_minimum": "Audit score is below the declared policy minimum.",
        "policy.control.required_not_passed": "A required control did not pass.",
        "policy.assurance.required_not_ready": "A required assurance capability is not ready.",
        "policy.finding.disallowed_severity": "A finding has a severity disallowed by policy.",
        "regression.score.regressed": "Audit score regressed beyond the approved tolerance.",
        "regression.profile.changed": "The selected endpoint profile changed.",
        "regression.target.changed": "The URL associated with a stable target id changed.",
        "regression.control.status_regressed": "A control status regressed.",
        "regression.control.severity_regressed": "A control severity regressed.",
        "regression.control.points_regressed": "A control score contribution regressed.",
        "regression.control.missing_from_run": "A baseline control is absent from the current run.",
        "regression.control.new_actionable_finding": "A new actionable finding was detected.",
        "regression.baseline.unapproved_target": "The target is not in the approved baseline.",
        "regression.baseline.orphaned_target": "A baseline target is absent from the policy.",
        "operational.audit_error": "The audit could not execute reliably.",
    }.get(rule_id, "Security headers assurance diagnostic.")
