from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from copy import deepcopy
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

from security_headers_auditor import METHODOLOGY_VERSION
from security_headers_auditor.auditor import audit_headers
from security_headers_auditor.workspace.migrations import (
    WorkspaceMigrationError,
    migrate_workspace,
)
from security_headers_auditor.workspace.repository import (
    WorkspaceConflictError,
    WorkspaceDatabaseVersionError,
    WorkspaceNotFoundError,
    WorkspaceRepository,
)
from security_headers_auditor.workspace.server import create_workspace_server
from security_headers_auditor.workspace.schema import (
    MAX_WORKSPACE_BYTES,
    WorkspaceValidationError,
    parse_workspace_bytes,
    validate_workspace,
)
from security_headers_auditor.workspace.security import (
    LoopbackRequestGuard,
    WorkspaceAuthorizationError,
    WorkspaceRequestError,
)
from security_headers_auditor.workspace.service import WorkspaceService


FIXTURES = Path(__file__).parent / "fixtures"


def workspace_payload() -> dict[str, object]:
    return {
        "schema_version": "1.2",
        "workspace_id": "5f0f84f3-1775-4de5-b2c8-3768c9d03f45",
        "name": "Fixture workspace",
        "policy": {
            "schema_version": "1.0",
            "methodology_version": METHODOLOGY_VERSION,
            "name": "fixture-policy",
            "defaults": {
                "fail_on_severity": ["high"],
                "allow_auto_profile": False,
            },
            "targets": [
                {
                    "id": "public-site",
                    "url": "https://example.test/",
                    "profile": "brochure",
                    "minimum_score": 75,
                    "maximum_score_drop": 0,
                    "required_controls": [
                        "strict-transport-security",
                        "content-security-policy",
                    ],
                    "reporting_readiness": "observe",
                    "cross_origin_isolation": "not_applicable",
                }
            ],
        },
        "disabled_target_ids": [],
        "approved_baseline": None,
        "latest_summaries": {},
        "audit_history": [],
        "created_at": "2026-07-19T10:00:00+00:00",
        "updated_at": "2026-07-19T10:00:00+00:00",
    }


def audit_from_fixture(name: str):
    fixture = json.loads(
        (FIXTURES / f"{name}_headers.json").read_text(encoding="utf-8")
    )

    def fixture_fetch(
        target: str,
        timeout: float = 8.0,
        allow_cross_origin_redirects: bool = False,
        allow_private_targets: bool = True,
    ):
        del target, timeout, allow_cross_origin_redirects, allow_private_targets
        return fixture["final_url"], fixture["status_code"], fixture["headers"]

    def fixture_audit(target: str, **kwargs):
        kwargs.pop("allow_private_targets", None)
        with patch(
            "security_headers_auditor.auditor.fetch_headers",
            fixture_fetch,
        ):
            return audit_headers(target, **kwargs)

    return fixture_audit


class WorkspaceSchemaTests(unittest.TestCase):
    def test_valid_workspace_passes(self):
        payload = workspace_payload()
        self.assertIs(validate_workspace(payload), payload)

    def test_unknown_field_is_rejected(self):
        payload = workspace_payload()
        payload["raw_headers"] = {"Server": "fixture"}
        with self.assertRaisesRegex(
            WorkspaceValidationError,
            "unknown fields: raw_headers",
        ):
            validate_workspace(payload)

    def test_disabled_target_ids_must_reference_unique_policy_targets(self):
        payload = workspace_payload()
        payload["disabled_target_ids"] = ["unknown", "unknown"]
        with self.assertRaisesRegex(WorkspaceValidationError, "duplicates"):
            validate_workspace(payload)
        payload["disabled_target_ids"] = ["unknown"]
        with self.assertRaisesRegex(WorkspaceValidationError, "unknown targets"):
            validate_workspace(payload)

    def test_summary_cannot_persist_raw_values(self):
        payload = workspace_payload()
        payload["latest_summaries"] = {
            "public-site": {
                "target_id": "public-site",
                "completed_at": "2026-07-19T10:30:00+00:00",
                "target": "https://example.test/",
                "selected_profile": "brochure",
                "score": 90,
                "outcome": "passed",
                "exit_code": 0,
                "findings": {
                    "strict-transport-security": {
                        "status": "pass",
                        "severity": "info",
                        "category": "scored",
                        "applicability": "required",
                        "points": 30,
                        "max_points": 30,
                        "value": "max-age=31536000",
                    }
                },
            }
        }
        with self.assertRaisesRegex(
            WorkspaceValidationError,
            "unknown fields: value",
        ):
            validate_workspace(payload)

    def test_import_size_and_utf8_are_checked_before_json(self):
        with self.assertRaisesRegex(WorkspaceValidationError, "exceeds"):
            parse_workspace_bytes(b" " * (MAX_WORKSPACE_BYTES + 1))
        with self.assertRaisesRegex(WorkspaceValidationError, "UTF-8"):
            parse_workspace_bytes(b"\xff")

    def test_import_round_trip_is_current_and_deterministic(self):
        raw = json.dumps(
            workspace_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        parsed, applied = parse_workspace_bytes(raw)
        self.assertEqual(parsed, workspace_payload())
        self.assertEqual(applied, ())

    def test_v1_0_workspace_migrates_to_current_schema_deterministically(self):
        legacy = workspace_payload()
        legacy["schema_version"] = "1.0"
        del legacy["disabled_target_ids"]
        del legacy["audit_history"]

        migrated, applied = parse_workspace_bytes(json.dumps(legacy).encode())

        self.assertEqual(migrated["schema_version"], "1.2")
        self.assertEqual(migrated["disabled_target_ids"], [])
        self.assertEqual(migrated["audit_history"], [])
        self.assertEqual(
            applied,
            ("workspace-1.0-to-1.1", "workspace-1.1-to-1.2"),
        )

    def test_v1_1_workspace_migrates_empty_audit_history_deterministically(self):
        legacy = workspace_payload()
        legacy["schema_version"] = "1.1"
        del legacy["audit_history"]

        migrated, applied = parse_workspace_bytes(json.dumps(legacy).encode())

        self.assertEqual(migrated["schema_version"], "1.2")
        self.assertEqual(migrated["audit_history"], [])
        self.assertEqual(applied, ("workspace-1.1-to-1.2",))

    def test_audit_history_rejects_raw_response_values_and_excess_entries(self):
        payload = workspace_payload()
        payload["audit_history"] = [
            {
                "audit_id": "c8a07661-4a6a-4bff-9d8a-1b0168e09d72",
                "completed_at": "2026-07-19T10:30:00+00:00",
                "run_kind": "target",
                "policy_name": "fixture-policy",
                "outcome": "passed",
                "exit_code": 0,
                "assessments": [
                    {
                        "target_id": "public-site",
                        "target": "https://example.test/",
                        "selected_profile": "brochure",
                        "score": 90,
                        "outcome": "passed",
                        "exit_code": 0,
                        "value": "max-age=31536000",
                    }
                ],
            }
        ]
        with self.assertRaisesRegex(
            WorkspaceValidationError,
            "unknown fields: value",
        ):
            validate_workspace(payload)

        payload["audit_history"] = [{}] * 51
        with self.assertRaisesRegex(WorkspaceValidationError, "50-entry"):
            validate_workspace(payload)

    def test_unknown_future_schema_is_rejected_without_mutation(self):
        payload = workspace_payload()
        payload["schema_version"] = "99.0"
        original = deepcopy(payload)
        with self.assertRaisesRegex(
            WorkspaceMigrationError,
            "Unsupported workspace schema",
        ):
            migrate_workspace(payload)
        self.assertEqual(payload, original)


class WorkspaceRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "workspace.sqlite3"
        self.repository = WorkspaceRepository(self.database)

    def tearDown(self):
        self.temporary.cleanup()

    def test_create_get_save_and_conflict(self):
        payload = workspace_payload()
        created = self.repository.create(payload)
        self.assertEqual(created.revision, 0)
        self.assertEqual(self.repository.get(payload["workspace_id"]), created)

        updated = deepcopy(payload)
        updated["name"] = "Updated fixture"
        updated["updated_at"] = "2026-07-19T11:00:00+00:00"
        saved = self.repository.save(updated, expected_revision=0)
        self.assertEqual(saved.revision, 1)
        self.assertEqual(saved.document["name"], "Updated fixture")

        with self.assertRaisesRegex(WorkspaceConflictError, "expected 0, current 1"):
            self.repository.save(payload, expected_revision=0)
        self.assertEqual(
            self.repository.get(payload["workspace_id"]).document["name"],
            "Updated fixture",
        )

    def test_duplicate_create_and_missing_workspace_are_explicit(self):
        payload = workspace_payload()
        self.repository.create(payload)
        with self.assertRaises(WorkspaceConflictError):
            self.repository.create(payload)
        with self.assertRaises(WorkspaceNotFoundError):
            self.repository.get("d102d3c2-ed83-4447-85f9-5945450e89b9")

    def test_delete_requires_current_revision(self):
        payload = workspace_payload()
        self.repository.create(payload)
        with self.assertRaises(WorkspaceConflictError):
            self.repository.delete(payload["workspace_id"], expected_revision=1)
        self.repository.delete(payload["workspace_id"], expected_revision=0)
        with self.assertRaises(WorkspaceNotFoundError):
            self.repository.get(payload["workspace_id"])

    def test_clear_all_returns_deleted_count(self):
        self.repository.create(workspace_payload())
        self.assertEqual(self.repository.clear_all(), 1)
        self.assertEqual(self.repository.list_workspaces(), ())

    def test_database_and_directory_permissions_are_restricted(self):
        if self.database.stat().st_mode & 0o777:
            self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.database.parent.stat().st_mode & 0o777, 0o700)

    def test_newer_physical_database_is_rejected(self):
        newer = Path(self.temporary.name) / "newer.sqlite3"
        with sqlite3.connect(newer) as connection:
            connection.execute("PRAGMA user_version = 99")
        with self.assertRaisesRegex(
            WorkspaceDatabaseVersionError,
            "newer than supported",
        ):
            WorkspaceRepository(newer)

    def test_revision_type_is_rejected_without_changing_state(self):
        payload = workspace_payload()
        self.repository.create(payload)
        with self.assertRaisesRegex(
            WorkspaceConflictError,
            "non-negative integer",
        ):
            self.repository.save(payload, expected_revision="0")  # type: ignore[arg-type]
        self.assertEqual(
            self.repository.get(payload["workspace_id"]).revision,
            0,
        )

    def test_failed_database_migration_rolls_back_and_creates_backup(self):
        legacy = Path(self.temporary.name) / "legacy.sqlite3"
        with sqlite3.connect(legacy) as connection:
            connection.execute("CREATE TABLE preserved (value TEXT NOT NULL)")
            connection.execute("INSERT INTO preserved VALUES ('original')")
        with patch(
            "security_headers_auditor.workspace.repository.DB_VERSION",
            2,
        ):
            with self.assertRaises(WorkspaceDatabaseVersionError):
                WorkspaceRepository(legacy)
        with sqlite3.connect(legacy) as connection:
            self.assertEqual(
                connection.execute("SELECT value FROM preserved").fetchone()[0],
                "original",
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE name = 'workspaces'"
                ).fetchone()
            )
        self.assertEqual(
            len(list(Path(self.temporary.name).glob("legacy.sqlite3.v0.*.bak"))),
            1,
        )


class WorkspaceServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = WorkspaceRepository(
            Path(self.temporary.name) / "workspace.sqlite3"
        )
        self.repository.create(workspace_payload())
        self.service = WorkspaceService(self.repository)
        self.workspace_id = str(workspace_payload()["workspace_id"])

    def tearDown(self):
        self.temporary.cleanup()

    def test_run_persists_minimal_summary_but_returns_detailed_evidence(self):
        with patch(
            "security_headers_auditor.workspace.service.audit_headers",
            audit_from_fixture("assurance_ready"),
        ):
            response = self.service.run(self.workspace_id, expected_revision=0)
        self.assertEqual(response["record"]["revision"], 1)
        summary = response["record"]["document"]["latest_summaries"]["public-site"]
        self.assertNotIn("value", json.dumps(summary))
        findings = response["run"]["assessments"][0]["result"]["findings"]
        self.assertTrue(any(finding.get("value") for finding in findings))
        html = self.service.export_current_report(self.workspace_id, "html")
        self.assertEqual(html["media_type"], "text/html")
        self.assertIn("Security Headers Audit Report", html["content"])
        self.assertNotIn("<script", html["content"].lower())
        sarif = self.service.export_current_report(self.workspace_id, "sarif")
        self.assertEqual(json.loads(sarif["content"])["version"], "2.1.0")

    def test_runs_keep_bounded_session_history_and_timestamped_export_names(self):
        completed_at = "2026-07-20T10:30:00+00:00"
        with patch(
            "security_headers_auditor.workspace.service.audit_headers",
            audit_from_fixture("assurance_ready"),
        ), patch(
            "security_headers_auditor.workspace.service._now",
            return_value=completed_at,
        ):
            first_response = self.service.run(
                self.workspace_id,
                expected_revision=0,
                target_id="public-site",
            )
            first_report = self.service.export_current_report(self.workspace_id, "html")
            second_response = self.service.run(
                self.workspace_id,
                expected_revision=first_response["record"]["revision"],
                target_id="public-site",
            )
            second_report = self.service.export_current_report(self.workspace_id, "html")

        history = second_response["record"]["document"]["audit_history"]
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["completed_at"], completed_at)
        self.assertEqual(history[0]["run_kind"], "target")
        self.assertEqual(history[0]["assessments"][0]["target_id"], "public-site")
        self.assertNotIn("value", json.dumps(history))
        self.assertNotEqual(first_report["filename"], second_report["filename"])
        self.assertRegex(
            first_report["filename"],
            r"^fixture-policy-public-site-20260720T103000Z-[0-9a-f]{8}-report\.html$",
        )
        self.assertRegex(
            second_report["filename"],
            r"^fixture-policy-public-site-20260720T103000Z-[0-9a-f]{8}-report\.html$",
        )

    def test_run_discards_only_the_oldest_session_after_history_limit(self):
        document = self.repository.get(self.workspace_id).document
        document["audit_history"] = [
            {
                "audit_id": f"00000000-0000-4000-8000-{index:012d}",
                "completed_at": "2026-07-19T10:30:00+00:00",
                "run_kind": "target",
                "policy_name": "fixture-policy",
                "outcome": "passed",
                "exit_code": 0,
                "assessments": [
                    {
                        "target_id": "public-site",
                        "target": "https://example.test/",
                        "selected_profile": "brochure",
                        "score": 90,
                        "outcome": "passed",
                        "exit_code": 0,
                    }
                ],
            }
            for index in range(50)
        ]
        seeded = self.repository.save(document, expected_revision=0)

        with patch(
            "security_headers_auditor.workspace.service.audit_headers",
            audit_from_fixture("assurance_ready"),
        ):
            response = self.service.run(
                self.workspace_id,
                expected_revision=seeded.revision,
                target_id="public-site",
            )

        history = response["record"]["document"]["audit_history"]
        self.assertEqual(len(history), 50)
        self.assertNotEqual(history[0]["audit_id"], "00000000-0000-4000-8000-000000000000")
        self.assertEqual(
            history[-1]["audit_id"],
            "00000000-0000-4000-8000-000000000048",
        )

    def test_persisted_session_history_and_summary_always_redact_target_query(self):
        document = self.repository.get(self.workspace_id).document
        document["policy"]["targets"][0]["url"] = (
            "https://example.test/fixture?token=fixture-secret#private"
        )
        document["policy"]["targets"][0]["include_query"] = True
        document["updated_at"] = "2026-07-20T10:30:00+00:00"
        configured = self.repository.save(document, expected_revision=0)

        with patch(
            "security_headers_auditor.workspace.service.audit_headers",
            audit_from_fixture("assurance_ready"),
        ):
            response = self.service.run(
                self.workspace_id,
                expected_revision=configured.revision,
                target_id="public-site",
            )

        persisted = response["record"]["document"]
        history_target = persisted["audit_history"][0]["assessments"][0]["target"]
        summary_target = persisted["latest_summaries"]["public-site"]["target"]
        self.assertNotIn("fixture-secret", history_target)
        self.assertNotIn("fixture-secret", summary_target)
        self.assertIn("<redacted>", history_target)
        self.assertIn("<redacted>", summary_target)

    def test_report_export_requires_a_current_in_memory_run(self):
        with self.assertRaisesRegex(ValueError, "run assurance first"):
            self.service.export_current_report(self.workspace_id, "html")

    def test_save_clears_summary_when_target_configuration_changes(self):
        with patch(
            "security_headers_auditor.workspace.service.audit_headers",
            audit_from_fixture("assurance_ready"),
        ):
            self.service.run(self.workspace_id, expected_revision=0)
        updated = self.repository.get(self.workspace_id).document
        self.assertIn("public-site", updated["latest_summaries"])
        updated["policy"]["targets"][0]["url"] = "https://replacement.example.test/"
        updated["updated_at"] = "2026-07-19T11:00:00+00:00"

        saved = self.service.save(self.workspace_id, updated, expected_revision=1)

        self.assertEqual(saved["revision"], 2)
        self.assertEqual(saved["document"]["latest_summaries"], {})
        self.assertEqual(len(saved["document"]["audit_history"]), 1)

    def test_disabled_targets_are_not_run_or_baselined(self):
        document = self.repository.get(self.workspace_id).document
        document["disabled_target_ids"] = ["public-site"]
        document["updated_at"] = "2026-07-19T11:00:00+00:00"
        saved = self.service.save(self.workspace_id, document, expected_revision=0)

        with self.assertRaisesRegex(ValueError, "Enable at least one"):
            self.service.run(self.workspace_id, expected_revision=saved["revision"])
        with self.assertRaisesRegex(ValueError, "is disabled"):
            self.service.run(
                self.workspace_id,
                expected_revision=saved["revision"],
                target_id="public-site",
            )

    def test_assurance_and_baseline_ignore_disabled_target(self):
        document = self.repository.get(self.workspace_id).document
        second = deepcopy(document["policy"]["targets"][0])
        second["id"] = "secondary-site"
        second["url"] = "https://secondary.example.test/"
        document["policy"]["targets"].append(second)
        document["disabled_target_ids"] = ["public-site"]
        document["updated_at"] = "2026-07-19T11:00:00+00:00"
        saved = self.service.save(self.workspace_id, document, expected_revision=0)

        with patch(
            "security_headers_auditor.workspace.service.audit_headers",
            audit_from_fixture("assurance_ready"),
        ):
            candidate = self.service.create_candidate_baseline(
                self.workspace_id,
                expected_revision=saved["revision"],
            )

        self.assertEqual(
            tuple(candidate["candidate"]["targets"]),
            ("secondary-site",),
        )

    def test_import_preview_is_non_mutating_and_commit_is_explicit(self):
        imported = workspace_payload()
        imported["workspace_id"] = "8f3fbb2a-7984-4d32-9b93-507d663cb824"
        imported["name"] = "Imported workspace"

        preview = self.service.preview_import(imported)

        self.assertEqual(preview["target_count"], 1)
        self.assertIsNone(preview["existing_workspace"])
        self.assertIsNone(preview["expected_revision"])
        with self.assertRaises(WorkspaceNotFoundError):
            self.repository.get(imported["workspace_id"])

        committed = self.service.commit_import(
            preview["document"],
            expected_revision=preview["expected_revision"],
        )

        self.assertEqual(committed["revision"], 0)
        self.assertEqual(committed["document"]["latest_summaries"], {})
        self.assertNotIn(imported["workspace_id"], self.service._runs)

    def test_import_replacement_requires_previewed_revision(self):
        imported = workspace_payload()
        imported["name"] = "Replacement workspace"
        imported["updated_at"] = "2026-07-19T11:00:00+00:00"

        preview = self.service.preview_import(imported)
        self.assertEqual(preview["expected_revision"], 0)
        with self.assertRaisesRegex(ValueError, "provide its revision"):
            self.service.commit_import(imported, expected_revision=None)
        self.assertEqual(
            self.repository.get(self.workspace_id).document["name"],
            "Fixture workspace",
        )

        committed = self.service.commit_import(
            preview["document"],
            expected_revision=preview["expected_revision"],
        )
        self.assertEqual(committed["revision"], 1)
        self.assertEqual(committed["document"]["name"], "Replacement workspace")

    def test_candidate_requires_pass_and_approval_is_separate_revision(self):
        with patch(
            "security_headers_auditor.workspace.service.audit_headers",
            audit_from_fixture("assurance_ready"),
        ):
            response = self.service.create_candidate_baseline(
                self.workspace_id,
                expected_revision=0,
            )
        self.assertIsNone(
            response["record"]["document"]["approved_baseline"]
        )
        self.assertEqual(response["diff"]["change_count"], 1)
        approved = self.service.approve_baseline(
            self.workspace_id,
            response["candidate"],
            expected_revision=response["record"]["revision"],
        )
        self.assertEqual(approved["record"]["revision"], 2)
        self.assertIsNotNone(
            approved["record"]["document"]["approved_baseline"]
        )

    def test_candidate_target_mismatch_is_rejected(self):
        with patch(
            "security_headers_auditor.workspace.service.audit_headers",
            audit_from_fixture("assurance_ready"),
        ):
            response = self.service.create_candidate_baseline(
                self.workspace_id,
                expected_revision=0,
            )
        candidate = deepcopy(response["candidate"])
        candidate["targets"]["unknown-target"] = candidate["targets"].pop(
            "public-site"
        )
        with self.assertRaisesRegex(ValueError, "exactly match"):
            self.service.approve_baseline(
                self.workspace_id,
                candidate,
                expected_revision=1,
            )
        self.assertIsNone(
            self.repository.get(self.workspace_id).document["approved_baseline"]
        )


class LoopbackRequestGuardTests(unittest.TestCase):
    def setUp(self):
        self.guard = LoopbackRequestGuard.create(port=8766)
        self.headers = {
            "Host": "127.0.0.1:8766",
            "Authorization": f"Bearer {self.guard.token}",
            "Origin": "http://127.0.0.1:8766",
            "Sec-Fetch-Site": "same-origin",
            "Content-Type": "application/json; charset=utf-8",
        }

    def test_same_origin_token_request_is_authorized(self):
        self.guard.authorize("POST", self.headers, content_length=128)

    def test_wrong_host_origin_token_and_fetch_site_are_rejected(self):
        mutations = {
            "Host": "attacker.test",
            "Origin": "https://attacker.test",
            "Authorization": "Bearer wrong",
            "Sec-Fetch-Site": "cross-site",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                headers = dict(self.headers)
                headers[field] = value
                with self.assertRaises(WorkspaceAuthorizationError):
                    self.guard.authorize("POST", headers, content_length=1)

    def test_state_change_requires_origin_and_json(self):
        missing_origin = dict(self.headers)
        del missing_origin["Origin"]
        with self.assertRaisesRegex(
            WorkspaceAuthorizationError,
            "require the workspace Origin",
        ):
            self.guard.authorize("POST", missing_origin, content_length=1)

        wrong_type = dict(self.headers)
        wrong_type["Content-Type"] = "text/plain"
        with self.assertRaisesRegex(
            WorkspaceRequestError,
            "application/json",
        ):
            self.guard.authorize("POST", wrong_type, content_length=1)

    def test_oversized_body_is_rejected(self):
        with self.assertRaisesRegex(WorkspaceRequestError, "exceeds"):
            self.guard.authorize(
                "POST",
                self.headers,
                content_length=MAX_WORKSPACE_BYTES + 1,
            )

    def test_non_loopback_guard_cannot_be_created(self):
        with self.assertRaisesRegex(ValueError, "127.0.0.1"):
            LoopbackRequestGuard.create(host="0.0.0.0")


class WorkspaceServerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        repository = WorkspaceRepository(
            Path(self.temporary.name) / "workspace.sqlite3"
        )
        self.server = create_workspace_server(repository, port=0)
        self.thread = threading.Thread(
            target=self.server.httpd.serve_forever,
            daemon=True,
        )
        self.thread.start()

    def tearDown(self):
        self.server.httpd.shutdown()
        self.server.httpd.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
        *,
        token: str | None = None,
        origin: str | None = None,
    ):
        encoded = None if body is None else json.dumps(body).encode()
        headers = {
            "Authorization": f"Bearer {token or self.server.guard.token}",
            "Sec-Fetch-Site": "same-origin",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
            headers["Origin"] = origin or self.server.guard.origin
        connection = HTTPConnection(
            self.server.guard.host,
            self.server.guard.port,
            timeout=2,
        )
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response, payload

    def test_static_workspace_is_loopback_hardened(self):
        response, payload = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertIn(b"Security Headers Auditor", payload)
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.assertIn(
            "default-src 'none'",
            response.getheader("Content-Security-Policy"),
        )

    def test_bootstrap_exposes_tool_and_methodology_versions_separately(self):
        response, payload = self.request("GET", "/api/v1/bootstrap")
        self.assertEqual(response.status, 200)
        bootstrap = json.loads(payload)
        self.assertEqual(bootstrap["tool_version"], "0.9.0")
        self.assertEqual(bootstrap["methodology_version"], METHODOLOGY_VERSION)

    def test_tokenless_and_cross_origin_api_requests_fail(self):
        response, _ = self.request(
            "GET",
            "/api/v1/bootstrap",
            token="wrong",
        )
        self.assertEqual(response.status, 403)
        response, _ = self.request(
            "POST",
            "/api/v1/workspaces",
            workspace_payload(),
            origin="https://attacker.test",
        )
        self.assertEqual(response.status, 403)

    def test_authorized_api_create_and_read_round_trip(self):
        response, payload = self.request(
            "POST",
            "/api/v1/workspaces",
            workspace_payload(),
        )
        self.assertEqual(response.status, 201)
        created = json.loads(payload)
        self.assertEqual(created["revision"], 0)
        response, payload = self.request(
            "GET",
            f"/api/v1/workspaces/{workspace_payload()['workspace_id']}",
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(
            json.loads(payload)["document"]["name"],
            "Fixture workspace",
        )

    def test_first_workspace_import_requires_preview_and_never_runs(self):
        response, payload = self.request(
            "POST",
            "/api/v1/workspace-imports/preview",
            {"document": workspace_payload()},
        )
        self.assertEqual(response.status, 200)
        preview = json.loads(payload)
        self.assertIsNone(preview["existing_workspace"])
        self.assertIsNone(preview["expected_revision"])

        response, payload = self.request(
            "POST",
            "/api/v1/workspace-imports/commit",
            {
                "document": preview["document"],
                "expected_revision": preview["expected_revision"],
            },
        )
        self.assertEqual(response.status, 200)
        committed = json.loads(payload)
        self.assertEqual(committed["revision"], 0)
        self.assertEqual(committed["document"]["latest_summaries"], {})


if __name__ == "__main__":
    unittest.main()
