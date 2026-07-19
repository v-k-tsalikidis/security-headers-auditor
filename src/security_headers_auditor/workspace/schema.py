"""Strict validation for portable workspace documents."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from ..assurance import (
    BASELINE_CONTROL_KEYS,
    BaselineCompatibilityError,
    PolicyConfigurationError,
    parse_policy,
    validate_baseline,
)
from .migrations import CURRENT_WORKSPACE_SCHEMA_VERSION


MAX_WORKSPACE_BYTES = 2 * 1024 * 1024
MAX_TARGETS = 100
MAX_NAME_LENGTH = 100
MAX_SUMMARIES = 100


class WorkspaceValidationError(ValueError):
    """Raised when a workspace document violates its portable contract."""


ROOT_FIELDS = {
    "schema_version",
    "workspace_id",
    "name",
    "policy",
    "approved_baseline",
    "latest_summaries",
    "created_at",
    "updated_at",
}

SUMMARY_FIELDS = {
    "target_id",
    "completed_at",
    "target",
    "selected_profile",
    "score",
    "outcome",
    "exit_code",
    "findings",
}

SUMMARY_FINDING_FIELDS = {
    "status",
    "severity",
    "category",
    "applicability",
    "points",
    "max_points",
}


def parse_workspace_bytes(raw: bytes) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Parse, migrate, and validate a bounded UTF-8 workspace import."""
    if len(raw) > MAX_WORKSPACE_BYTES:
        raise WorkspaceValidationError(
            f"Workspace import exceeds {MAX_WORKSPACE_BYTES} bytes."
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WorkspaceValidationError(
            "Workspace import must be UTF-8 JSON."
        ) from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise WorkspaceValidationError(
            f"Workspace import is not valid JSON: line {exc.lineno}, "
            f"column {exc.colno}."
        ) from exc
    from .migrations import migrate_workspace

    try:
        migrated = migrate_workspace(payload)
    except ValueError as exc:
        raise WorkspaceValidationError(str(exc)) from exc
    validate_workspace(migrated.document)
    return migrated.document, migrated.applied


def validate_workspace(payload: dict[str, Any]) -> dict[str, Any]:
    """Validate a current-schema workspace and return it unchanged."""
    if not isinstance(payload, dict):
        raise WorkspaceValidationError("Workspace root must be a JSON object.")
    _require_exact_fields(payload, ROOT_FIELDS, "workspace")

    if payload["schema_version"] != CURRENT_WORKSPACE_SCHEMA_VERSION:
        raise WorkspaceValidationError(
            f"Workspace schema {payload['schema_version']!r} is not current; expected "
            f"{CURRENT_WORKSPACE_SCHEMA_VERSION!r}."
        )
    _uuid(payload["workspace_id"], "workspace_id")
    _bounded_string(payload["name"], "name", MAX_NAME_LENGTH)
    _timestamp(payload["created_at"], "created_at")
    _timestamp(payload["updated_at"], "updated_at")

    policy_payload = payload["policy"]
    try:
        policy = parse_policy(policy_payload)
    except PolicyConfigurationError as exc:
        raise WorkspaceValidationError(f"Invalid workspace policy: {exc}") from exc
    if len(policy.targets) > MAX_TARGETS:
        raise WorkspaceValidationError(
            f"Workspace policy exceeds the {MAX_TARGETS}-target limit."
        )

    baseline = payload["approved_baseline"]
    if baseline is not None:
        try:
            validate_baseline(baseline)
        except BaselineCompatibilityError as exc:
            raise WorkspaceValidationError(
                f"Invalid approved baseline: {exc}"
            ) from exc
        if baseline["policy_name"] != policy.name:
            raise WorkspaceValidationError(
                "Approved baseline policy_name must match the workspace policy."
            )

    summaries = payload["latest_summaries"]
    if not isinstance(summaries, dict):
        raise WorkspaceValidationError(
            "latest_summaries must be a JSON object keyed by target id."
        )
    if len(summaries) > MAX_SUMMARIES:
        raise WorkspaceValidationError(
            f"Workspace exceeds the {MAX_SUMMARIES}-summary limit."
        )
    target_ids = {target.id for target in policy.targets}
    unknown_summaries = set(summaries) - target_ids
    if unknown_summaries:
        raise WorkspaceValidationError(
            "Summaries reference unknown targets: "
            + ", ".join(sorted(unknown_summaries))
        )
    for target_id, summary in summaries.items():
        _validate_summary(target_id, summary)

    return payload


def _validate_summary(target_id: str, summary: Any) -> None:
    if not isinstance(summary, dict):
        raise WorkspaceValidationError(
            f"Summary {target_id!r} must be a JSON object."
        )
    _require_exact_fields(summary, SUMMARY_FIELDS, f"summary {target_id!r}")
    if summary["target_id"] != target_id:
        raise WorkspaceValidationError(
            f"Summary key {target_id!r} does not match its target_id."
        )
    _timestamp(summary["completed_at"], f"{target_id}.completed_at")
    _safe_target(summary["target"], f"{target_id}.target")
    if summary["selected_profile"] not in {"app", "api", "brochure"}:
        raise WorkspaceValidationError(
            f"{target_id}.selected_profile is invalid."
        )
    _bounded_integer(summary["score"], f"{target_id}.score", 0, 100)
    if summary["outcome"] not in {"passed", "failed", "operational_error"}:
        raise WorkspaceValidationError(f"{target_id}.outcome is invalid.")
    _bounded_integer(summary["exit_code"], f"{target_id}.exit_code", 0, 2)

    findings = summary["findings"]
    if not isinstance(findings, dict):
        raise WorkspaceValidationError(
            f"{target_id}.findings must be a JSON object."
        )
    unknown_controls = set(findings) - BASELINE_CONTROL_KEYS
    if unknown_controls:
        raise WorkspaceValidationError(
            f"{target_id}.findings contains unknown controls: "
            + ", ".join(sorted(unknown_controls))
        )
    for control_key, finding in findings.items():
        if not isinstance(finding, dict):
            raise WorkspaceValidationError(
                f"{target_id}.{control_key} must be a JSON object."
            )
        _require_exact_fields(
            finding,
            SUMMARY_FINDING_FIELDS,
            f"{target_id}.{control_key}",
        )
        for field in ("status", "severity", "category", "applicability"):
            _bounded_string(
                finding[field],
                f"{target_id}.{control_key}.{field}",
                64,
            )
        _number(
            finding["points"],
            f"{target_id}.{control_key}.points",
            0,
            100,
        )
        _number(
            finding["max_points"],
            f"{target_id}.{control_key}.max_points",
            0,
            100,
        )


def _require_exact_fields(
    payload: dict[str, Any],
    expected: set[str],
    context: str,
) -> None:
    missing = expected - payload.keys()
    unknown = payload.keys() - expected
    if missing:
        raise WorkspaceValidationError(
            f"{context} is missing fields: " + ", ".join(sorted(missing))
        )
    if unknown:
        raise WorkspaceValidationError(
            f"{context} contains unknown fields: " + ", ".join(sorted(unknown))
        )


def _uuid(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise WorkspaceValidationError(f"{field} must be a UUID string.")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise WorkspaceValidationError(f"{field} must be a valid UUID.") from exc
    if str(parsed) != value.lower():
        raise WorkspaceValidationError(f"{field} must use canonical UUID form.")


def _timestamp(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise WorkspaceValidationError(f"{field} must be an ISO 8601 timestamp.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WorkspaceValidationError(
            f"{field} must be an ISO 8601 timestamp."
        ) from exc
    if parsed.tzinfo is None:
        raise WorkspaceValidationError(f"{field} must include a timezone.")


def _safe_target(value: Any, field: str) -> None:
    _bounded_string(value, field, 2048)
    parsed = urlparse(value.replace("<redacted>", "redacted"))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise WorkspaceValidationError(f"{field} must be a redacted HTTP(S) URL.")
    if parsed.username or parsed.password:
        raise WorkspaceValidationError(f"{field} must not contain credentials.")


def _bounded_string(value: Any, field: str, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip():
        raise WorkspaceValidationError(f"{field} must be a non-empty string.")
    if len(value) > maximum:
        raise WorkspaceValidationError(
            f"{field} must be at most {maximum} characters."
        )


def _bounded_integer(
    value: Any,
    field: str,
    minimum: int,
    maximum: int,
) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WorkspaceValidationError(f"{field} must be an integer.")
    if not minimum <= value <= maximum:
        raise WorkspaceValidationError(
            f"{field} must be between {minimum} and {maximum}."
        )


def _number(
    value: Any,
    field: str,
    minimum: float,
    maximum: float,
) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise WorkspaceValidationError(f"{field} must be numeric.")
    if not minimum <= float(value) <= maximum:
        raise WorkspaceValidationError(
            f"{field} must be between {minimum} and {maximum}."
        )
