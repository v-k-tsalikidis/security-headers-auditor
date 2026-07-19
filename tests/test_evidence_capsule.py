from __future__ import annotations

import json
import unittest
import warnings
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from jsonschema import Draft202012Validator

from security_headers_auditor.assurance import create_baseline, parse_policy, run_assurance
from security_headers_auditor.auditor import audit_headers
from security_headers_auditor.ci_report import (
    assurance_review_dict,
    render_assurance_review_json,
)
from security_headers_auditor.cli import main
from security_headers_auditor.evidence_capsule import (
    EvidenceCapsuleError,
    create_evidence_capsule,
    verify_evidence_capsule,
)
from security_headers_auditor.route_comparison import (
    create_route_baseline,
    parse_route_comparison,
    render_route_assurance_review_json,
    run_route_assurance,
)


FIXTURES = Path(__file__).parent / "fixtures"


def _fixture_audit(name: str):
    fixture = json.loads((FIXTURES / f"{name}_headers.json").read_text(encoding="utf-8"))

    def fetch(target: str, timeout: float = 8.0, allow_cross_origin_redirects: bool = False):
        del target, timeout, allow_cross_origin_redirects
        return fixture["final_url"], fixture["status_code"], fixture["headers"]

    def audit(target: str, **kwargs):
        with patch("security_headers_auditor.auditor.fetch_headers", fetch):
            return audit_headers(target, **kwargs)

    return audit


def _policy_payload(url: str = "https://secure.example.test/dashboard") -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "methodology_version": "0.5.0",
        "name": "capsule-fixture-policy",
        "defaults": {"allow_auto_profile": False, "fail_on_severity": []},
        "targets": [
            {
                "id": "portal",
                "url": url,
                "profile": "app",
                "minimum_score": 0,
                "maximum_score_drop": 0,
                "required_controls": [],
                "reporting_readiness": "observe",
                "cross_origin_isolation": "observe",
            }
        ],
    }


def _route_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "name": "capsule fixture routes",
        "origin": "https://portal.example.test",
        "routes": [
            {"id": "dashboard", "path": "/dashboard", "profile": "app"},
            {"id": "settings", "path": "/settings", "profile": "app"},
        ],
    }


class EvidenceCapsuleTests(unittest.TestCase):
    def _write_policy_sources(self, directory: Path) -> tuple[Path, Path, Path]:
        policy_payload = _policy_payload()
        policy_path = directory / "policy.json"
        policy_path.write_text(json.dumps(policy_payload), encoding="utf-8")
        initial_run = run_assurance(
            parse_policy(policy_payload), audit_function=_fixture_audit("assurance_ready")
        )
        baseline_payload = create_baseline(initial_run)
        run = run_assurance(
            parse_policy(policy_payload),
            baseline=baseline_payload,
            audit_function=_fixture_audit("assurance_ready"),
        )
        self.assertEqual(run.outcome, "passed")
        assessment_path = directory / "assessment.json"
        assessment_path.write_text(render_assurance_review_json(run), encoding="utf-8")
        baseline_path = directory / "baseline.json"
        baseline_path.write_text(
            json.dumps(baseline_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return policy_path, assessment_path, baseline_path

    def test_policy_capsule_is_deterministic_verified_and_data_minimized(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            policy, assessment, baseline = self._write_policy_sources(directory)
            first = directory / "first.shac"
            second = directory / "second.shac"
            verified = create_evidence_capsule(
                first,
                policy_path=policy,
                assessment_path=assessment,
                baseline_path=baseline,
            )
            repeated = create_evidence_capsule(
                second,
                policy_path=policy,
                assessment_path=assessment,
                baseline_path=baseline,
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(verified, repeated)
            self.assertEqual(verified.scope_kind, "policy")
            self.assertEqual(verified.scope_name, "capsule-fixture-policy")
            self.assertTrue(verified.has_baseline)
            self.assertEqual(verify_evidence_capsule(first), verified)
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    archive.namelist(),
                    [
                        "assessment.json",
                        "baseline.json",
                        "capsule-manifest.json",
                        "profile-definitions.json",
                        "scope.json",
                    ],
                )
                combined = b"".join(archive.read(name) for name in archive.namelist())
                manifest = json.loads(archive.read("capsule-manifest.json"))
            self.assertNotIn(b"default-src 'self'", combined)
            self.assertNotIn(b"fixture-value", combined)
            schema = json.loads(
                (
                    Path(__file__).parents[1]
                    / "docs"
                    / "schemas"
                    / "evidence-capsule-manifest.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(manifest)

    def test_route_capsule_binds_the_exact_manifest_and_baseline(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            manifest_payload = _route_payload()
            manifest = directory / "routes.json"
            manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
            config = parse_route_comparison(manifest_payload)
            initial_run = run_route_assurance(config, audit_function=_fixture_audit("app"))
            baseline_payload = create_route_baseline(initial_run.comparison)
            run = run_route_assurance(
                config,
                baseline=baseline_payload,
                audit_function=_fixture_audit("app"),
            )
            assessment = directory / "route-assessment.json"
            assessment.write_text(render_route_assurance_review_json(run), encoding="utf-8")
            baseline = directory / "route-baseline.json"
            baseline.write_text(
                json.dumps(baseline_payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            capsule = directory / "routes.shac"
            verified = create_evidence_capsule(
                capsule,
                route_comparison_path=manifest,
                assessment_path=assessment,
                baseline_path=baseline,
            )
            self.assertEqual(verified.scope_kind, "route-comparison")
            self.assertEqual(verified.scope_name, "capsule fixture routes")
            self.assertTrue(verified.has_baseline)

    def test_cli_emits_compact_review_json_for_policy_and_routes(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            policy, _, baseline = self._write_policy_sources(directory)
            policy_output = directory / "policy-review.json"
            policy_payload = _policy_payload()
            initial_policy_run = run_assurance(
                parse_policy(policy_payload), audit_function=_fixture_audit("assurance_ready")
            )
            policy_run = run_assurance(
                parse_policy(policy_payload),
                baseline=create_baseline(initial_policy_run),
                audit_function=_fixture_audit("assurance_ready"),
            )
            with patch("security_headers_auditor.cli.run_assurance", return_value=policy_run):
                self.assertEqual(
                    main(
                        [
                            "--policy",
                            str(policy),
                            "--baseline",
                            str(baseline),
                            "--format",
                            "review-json",
                            "--output",
                            str(policy_output),
                        ]
                    ),
                    0,
                )
            policy_review = json.loads(policy_output.read_text(encoding="utf-8"))
            self.assertEqual(policy_review["artifact"], "security-headers-auditor.assurance-review")
            self.assertNotIn("secure.example.test", policy_output.read_text(encoding="utf-8"))

            manifest_payload = _route_payload()
            manifest = directory / "routes.json"
            manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
            config = parse_route_comparison(manifest_payload)
            initial_route_run = run_route_assurance(
                config, audit_function=_fixture_audit("app")
            )
            route_baseline = directory / "route-baseline.json"
            route_baseline.write_text(
                json.dumps(
                    create_route_baseline(initial_route_run.comparison),
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            route_run = run_route_assurance(
                config,
                baseline=create_route_baseline(initial_route_run.comparison),
                audit_function=_fixture_audit("app"),
            )
            route_output = directory / "route-review.json"
            with patch("security_headers_auditor.cli.run_route_assurance", return_value=route_run):
                self.assertEqual(
                    main(
                        [
                            "--route-comparison",
                            str(manifest),
                            "--route-baseline",
                            str(route_baseline),
                            "--format",
                            "review-json",
                            "--output",
                            str(route_output),
                        ]
                    ),
                    0,
                )
            route_review = json.loads(route_output.read_text(encoding="utf-8"))
            self.assertEqual(
                route_review["artifact"], "security-headers-auditor.route-assurance-review"
            )
            self.assertNotIn("portal.example.test", route_output.read_text(encoding="utf-8"))

    def test_verifier_rejects_content_tampering_and_duplicate_entries(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            policy, assessment, baseline = self._write_policy_sources(directory)
            capsule = directory / "source.shac"
            create_evidence_capsule(
                capsule,
                policy_path=policy,
                assessment_path=assessment,
                baseline_path=baseline,
            )
            tampered = directory / "tampered.shac"
            with zipfile.ZipFile(capsule) as source, zipfile.ZipFile(
                tampered, "w", compression=zipfile.ZIP_STORED
            ) as destination:
                for name in source.namelist():
                    data = source.read(name)
                    if name == "assessment.json":
                        data = data.replace(b'"outcome":"passed"', b'"outcome":"failed"')
                    destination.writestr(name, data)
            with self.assertRaises(EvidenceCapsuleError):
                verify_evidence_capsule(tampered)

            duplicate = directory / "duplicate.shac"
            duplicate.write_bytes(capsule.read_bytes())
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate, "a", compression=zipfile.ZIP_STORED) as archive:
                    archive.writestr("scope.json", b"{}\n")
            with self.assertRaises(EvidenceCapsuleError):
                verify_evidence_capsule(duplicate)

    def test_creation_rejects_query_bearing_scope_and_non_review_assessment(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            query_policy = directory / "query-policy.json"
            query_policy.write_text(
                json.dumps(_policy_payload("https://secure.example.test/dashboard?token=never-store")),
                encoding="utf-8",
            )
            assessment = directory / "assessment.json"
            assessment.write_text(json.dumps({"unexpected": "report"}), encoding="utf-8")
            with self.assertRaises(EvidenceCapsuleError):
                create_evidence_capsule(
                    directory / "query.shac",
                    policy_path=query_policy,
                    assessment_path=assessment,
                )

            policy, valid_assessment, _ = self._write_policy_sources(directory)
            broad_report = directory / "broad-report.json"
            broad_report.write_text(
                json.dumps({"assessment": assurance_review_dict(run_assurance(parse_policy(_policy_payload()), audit_function=_fixture_audit("assurance_ready")))}),
                encoding="utf-8",
            )
            with self.assertRaises(EvidenceCapsuleError):
                create_evidence_capsule(
                    directory / "broad.shac",
                    policy_path=policy,
                    assessment_path=broad_report,
                )
            self.assertTrue(valid_assessment.exists())

    def test_cli_capsule_creation_never_calls_the_audit_engine(self):
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            policy, assessment, baseline = self._write_policy_sources(directory)
            output = directory / "offline.shac"
            with patch("security_headers_auditor.cli.audit_headers") as audit, redirect_stdout(StringIO()):
                self.assertEqual(
                    main(
                        [
                            "--create-evidence-capsule",
                            str(output),
                            "--capsule-policy",
                            str(policy),
                            "--capsule-assessment",
                            str(assessment),
                            "--capsule-baseline",
                            str(baseline),
                        ]
                    ),
                    0,
                )
            audit.assert_not_called()
            with redirect_stdout(StringIO()):
                self.assertEqual(main(["--verify-evidence-capsule", str(output)]), 0)

    def test_cli_rejects_capsule_mode_combined_with_audit_options(self):
        with TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "offline.shac"
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as raised:
                main(["--verify-evidence-capsule", str(output), "--timeout", "1"])
            self.assertEqual(raised.exception.code, 2)
