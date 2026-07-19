"""Application service shared by the loopback API and tests."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any

from ..assurance import (
    AssuranceRun,
    assurance_run_dict,
    create_baseline,
    parse_policy,
    run_assurance,
    validate_baseline,
)
from ..auditor import audit_headers
from ..ci_report import render_assurance_json, render_junit, render_sarif
from ..report import render_html, render_markdown
from .migrations import CURRENT_WORKSPACE_SCHEMA_VERSION
from .repository import WorkspaceRecord, WorkspaceRepository


class WorkspaceService:
    """Coordinate persistence and the existing assurance engine."""

    def __init__(
        self,
        repository: WorkspaceRepository,
        allow_private_targets: bool = False,
    ):
        self.repository = repository
        self.allow_private_targets = allow_private_targets
        self._runs: dict[str, AssuranceRun] = {}
        self._runs_lock = RLock()

    def bootstrap(self) -> dict[str, Any]:
        from .. import __version__
        from ..compliance import MAPPING_SET_VERSION

        return {
            "tool_version": __version__,
            "workspace_schema_version": CURRENT_WORKSPACE_SCHEMA_VERSION,
            "mapping_set_version": MAPPING_SET_VERSION,
            "allow_private_targets": self.allow_private_targets,
            "workspaces": list(self.repository.list_workspaces()),
        }

    def get(self, workspace_id: str) -> dict[str, Any]:
        return _record_payload(self.repository.get(workspace_id))

    def create(self, document: dict[str, Any]) -> dict[str, Any]:
        return _record_payload(self.repository.create(document))

    def save(
        self,
        workspace_id: str,
        document: dict[str, Any],
        expected_revision: int,
    ) -> dict[str, Any]:
        if document.get("workspace_id") != workspace_id:
            raise ValueError("Workspace path id and document id must match.")
        saved = _record_payload(
            self.repository.save(document, expected_revision=expected_revision)
        )
        with self._runs_lock:
            self._runs.pop(workspace_id, None)
        return saved

    def delete(self, workspace_id: str, expected_revision: int) -> None:
        self.repository.delete(workspace_id, expected_revision)
        with self._runs_lock:
            self._runs.pop(workspace_id, None)

    def run(
        self,
        workspace_id: str,
        expected_revision: int,
        target_id: str | None = None,
    ) -> dict[str, Any]:
        saved, run = self._execute_run(
            workspace_id,
            expected_revision,
            target_id=target_id,
            use_approved_baseline=True,
        )
        return {
            "record": _record_payload(saved),
            "run": assurance_run_dict(run),
        }

    def create_candidate_baseline(
        self,
        workspace_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        """Run policy assurance and return a review-only baseline candidate."""
        previous = self.repository.get(workspace_id).document["approved_baseline"]
        saved, run = self._execute_run(
            workspace_id,
            expected_revision,
            target_id=None,
            use_approved_baseline=False,
        )
        candidate = create_baseline(run)
        return {
            "record": _record_payload(saved),
            "run": assurance_run_dict(run),
            "candidate": candidate,
            "diff": _baseline_diff(previous, candidate),
        }

    def approve_baseline(
        self,
        workspace_id: str,
        candidate: dict[str, Any],
        expected_revision: int,
    ) -> dict[str, Any]:
        """Persist an explicitly reviewed baseline candidate."""
        record = self.repository.get(workspace_id)
        if record.revision != expected_revision:
            from .repository import WorkspaceConflictError

            raise WorkspaceConflictError(
                f"Workspace revision conflict: expected {expected_revision}, "
                f"current {record.revision}."
            )
        validate_baseline(candidate)
        document = deepcopy(record.document)
        policy = parse_policy(document["policy"])
        expected_targets = {target.id for target in policy.targets}
        candidate_targets = set(candidate["targets"])
        if candidate["policy_name"] != policy.name:
            raise ValueError(
                "Candidate baseline policy_name does not match the workspace policy."
            )
        if candidate_targets != expected_targets:
            raise ValueError(
                "Candidate baseline targets must exactly match the workspace policy."
            )
        document["approved_baseline"] = deepcopy(candidate)
        document["updated_at"] = _now()
        saved = self.repository.save(
            document,
            expected_revision=expected_revision,
        )
        return {
            "record": _record_payload(saved),
            "approved": deepcopy(candidate),
        }

    def export_current_report(
        self,
        workspace_id: str,
        report_format: str,
    ) -> dict[str, str]:
        """Render an explicit export from the current in-memory run."""
        self.repository.get(workspace_id)
        with self._runs_lock:
            run = self._runs.get(workspace_id)
        if run is None:
            raise ValueError(
                "No current in-memory run is available; run assurance first."
            )
        results = [assessment.result for assessment in run.assessments]
        renderers = {
            "html": (
                "text/html",
                "html",
                lambda: render_html(results, assurance_run=run),
            ),
            "markdown": (
                "text/markdown",
                "md",
                lambda: render_markdown(results, assurance_run=run),
            ),
            "json": (
                "application/json",
                "json",
                lambda: render_assurance_json(run),
            ),
            "sarif": (
                "application/sarif+json",
                "sarif.json",
                lambda: render_sarif(run),
            ),
            "junit": (
                "application/xml",
                "junit.xml",
                lambda: render_junit(run),
            ),
        }
        selected = renderers.get(report_format)
        if selected is None:
            raise ValueError(
                "Report format must be html, markdown, json, sarif, or junit."
            )
        media_type, extension, render = selected
        return {
            "format": report_format,
            "media_type": media_type,
            "filename": f"{_filename(run.policy_name)}-report.{extension}",
            "content": render(),
        }

    def _execute_run(
        self,
        workspace_id: str,
        expected_revision: int,
        target_id: str | None,
        use_approved_baseline: bool,
    ) -> tuple[WorkspaceRecord, AssuranceRun]:
        record = self.repository.get(workspace_id)
        if record.revision != expected_revision:
            from .repository import WorkspaceConflictError

            raise WorkspaceConflictError(
                f"Workspace revision conflict: expected {expected_revision}, "
                f"current {record.revision}."
            )
        document = deepcopy(record.document)
        policy_payload = deepcopy(document["policy"])
        if target_id is not None:
            selected = [
                item
                for item in policy_payload["targets"]
                if item.get("id") == target_id
            ]
            if not selected:
                raise ValueError(f"Unknown workspace target {target_id!r}.")
            policy_payload["targets"] = selected
        policy = parse_policy(policy_payload)

        baseline = (
            _select_baseline(document["approved_baseline"], target_id)
            if use_approved_baseline
            else None
        )

        def workspace_audit(target: str, **kwargs: Any):
            return audit_headers(
                target,
                **kwargs,
                allow_private_targets=self.allow_private_targets,
            )

        run = run_assurance(
            policy,
            baseline=baseline,
            audit_function=workspace_audit,
        )
        with self._runs_lock:
            self._runs[workspace_id] = run
        completed_at = _now()
        summaries = dict(document["latest_summaries"])
        summaries.update(_summaries_from_run(run, completed_at))
        document["latest_summaries"] = summaries
        document["updated_at"] = completed_at
        saved = self.repository.save(
            document,
            expected_revision=expected_revision,
        )
        return saved, run


def _select_baseline(
    baseline: dict[str, Any] | None,
    target_id: str | None,
) -> dict[str, Any] | None:
    if baseline is None or target_id is None:
        return deepcopy(baseline)
    selected = baseline.get("targets", {}).get(target_id)
    if selected is None:
        return None
    result = deepcopy(baseline)
    result["targets"] = {target_id: deepcopy(selected)}
    return result


def _summaries_from_run(
    run: AssuranceRun,
    completed_at: str,
) -> dict[str, dict[str, Any]]:
    return {
        assessment.target_id: {
            "target_id": assessment.target_id,
            "completed_at": completed_at,
            "target": assessment.result.target,
            "selected_profile": (
                assessment.result.selected_profile or assessment.policy.profile
            ),
            "score": assessment.result.score,
            "outcome": (
                "operational_error"
                if assessment.result.error
                else _target_outcome(run, assessment.target_id)
            ),
            "exit_code": (
                2
                if assessment.result.error
                else (1 if _target_failed(run, assessment.target_id) else 0)
            ),
            "findings": {
                finding.key: {
                    "status": finding.status,
                    "severity": finding.severity,
                    "category": finding.category,
                    "applicability": finding.applicability,
                    "points": finding.points,
                    "max_points": finding.max_points,
                }
                for finding in sorted(
                    assessment.result.findings,
                    key=lambda item: item.key,
                )
            },
        }
        for assessment in run.assessments
    }


def _target_failed(run: AssuranceRun, target_id: str) -> bool:
    return any(
        item.target_id == target_id
        for item in (*run.policy_violations, *run.regressions)
    )


def _target_outcome(run: AssuranceRun, target_id: str) -> str:
    return "failed" if _target_failed(run, target_id) else "passed"


def _record_payload(record: WorkspaceRecord) -> dict[str, Any]:
    return {
        "revision": record.revision,
        "document": record.document,
    }


def _baseline_diff(
    previous: dict[str, Any] | None,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    previous_targets = previous.get("targets", {}) if previous else {}
    candidate_targets = candidate["targets"]
    target_ids = sorted(set(previous_targets) | set(candidate_targets))
    changes: list[dict[str, Any]] = []
    for target_id in target_ids:
        before = previous_targets.get(target_id)
        after = candidate_targets.get(target_id)
        if before is None:
            changes.append(
                {
                    "target_id": target_id,
                    "change": "added",
                    "previous_score": None,
                    "candidate_score": after["score"],
                    "changed_controls": sorted(after["findings"]),
                }
            )
            continue
        if after is None:
            changes.append(
                {
                    "target_id": target_id,
                    "change": "removed",
                    "previous_score": before["score"],
                    "candidate_score": None,
                    "changed_controls": sorted(before["findings"]),
                }
            )
            continue
        control_keys = sorted(set(before["findings"]) | set(after["findings"]))
        changed_controls = [
            control_key
            for control_key in control_keys
            if before["findings"].get(control_key)
            != after["findings"].get(control_key)
        ]
        if (
            before["score"] != after["score"]
            or before["selected_profile"] != after["selected_profile"]
            or changed_controls
        ):
            changes.append(
                {
                    "target_id": target_id,
                    "change": "changed",
                    "previous_score": before["score"],
                    "candidate_score": after["score"],
                    "changed_controls": changed_controls,
                }
            )
    return {
        "previous_present": previous is not None,
        "change_count": len(changes),
        "targets": changes,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _filename(value: str) -> str:
    cleaned = "".join(
        character.lower() if character.isalnum() else "-"
        for character in value
    )
    return "-".join(part for part in cleaned.split("-") if part) or "assurance"
