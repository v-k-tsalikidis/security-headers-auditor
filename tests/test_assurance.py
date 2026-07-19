from __future__ import annotations

import json
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from xml.etree.ElementTree import fromstring

from jsonschema import Draft202012Validator, Draft7Validator

from security_headers_auditor import METHODOLOGY_VERSION, __version__
from security_headers_auditor.assurance import (
    BaselineCompatibilityError,
    PolicyConfigurationError,
    compare_baseline,
    create_baseline,
    parse_policy,
    run_assurance,
    validate_baseline,
)
from security_headers_auditor.assurance_controls import (
    analyze_cross_origin_isolation,
    analyze_reporting_readiness,
)
from security_headers_auditor.auditor import audit_headers
from security_headers_auditor.ci_report import (
    render_assurance_json,
    render_junit,
    render_sarif,
)
from security_headers_auditor.compliance import (
    MAPPING_MANIFEST,
    MAPPING_SET_VERSION,
    mappings_for_control,
)
from security_headers_auditor.report import render_html, render_markdown


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / f"{name}_headers.json").read_text(encoding="utf-8"))


def audit_from_fixture(name: str):
    fixture = load_fixture(name)

    def fixture_fetch(
        target: str,
        timeout: float = 8.0,
        allow_cross_origin_redirects: bool = False,
    ):
        del target, timeout, allow_cross_origin_redirects
        return fixture["final_url"], fixture["status_code"], fixture["headers"]

    def fixture_audit(target: str, **kwargs):
        with patch(
            "security_headers_auditor.auditor.fetch_headers",
            fixture_fetch,
        ):
            return audit_headers(target, **kwargs)

    return fixture_audit


def policy_payload(**target_overrides):
    target = {
        "id": "secure-portal",
        "url": "https://secure.example.test/dashboard",
        "profile": "app",
        "minimum_score": 90,
        "maximum_score_drop": 0,
        "required_controls": [
            "strict-transport-security",
            "content-security-policy",
        ],
        "reporting_readiness": "required",
        "cross_origin_isolation": "required",
    }
    target.update(target_overrides)
    return {
        "schema_version": "1.0",
        "methodology_version": METHODOLOGY_VERSION,
        "name": "fixture-assurance",
        "defaults": {
            "fail_on_severity": ["high"],
            "allow_auto_profile": False,
        },
        "targets": [target],
    }


class ReportingReadinessTests(unittest.TestCase):
    def test_modern_reporting_endpoint_and_csp_linkage_pass(self):
        fixture = load_fixture("assurance_ready")
        findings = analyze_reporting_readiness(
            {key.lower(): value for key, value in fixture["headers"].items()},
            fixture["final_url"],
            "required",
        )
        self.assertEqual([finding.status for finding in findings], ["pass", "pass"])

    def test_untrustworthy_endpoint_and_missing_group_warn(self):
        fixture = load_fixture("assurance_broken")
        findings = analyze_reporting_readiness(
            {key.lower(): value for key, value in fixture["headers"].items()},
            fixture["final_url"],
            "required",
        )
        self.assertEqual(findings[0].status, "warning")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[1].status, "warning")
        self.assertIn("missing-group", findings[1].note)

    def test_legacy_report_uri_is_explicitly_partial(self):
        findings = analyze_reporting_readiness(
            {
                "content-security-policy": (
                    "default-src 'self'; report-uri /csp-reports"
                )
            },
            "https://example.test/",
            "recommended",
        )
        self.assertEqual(findings[1].status, "review")
        self.assertIn("legacy", findings[1].note.lower())

    def test_relative_modern_endpoint_resolves_against_response(self):
        findings = analyze_reporting_readiness(
            {
                "reporting-endpoints": 'csp="/reports/csp"',
                "content-security-policy": (
                    "default-src 'self'; report-to csp"
                ),
            },
            "https://example.test/app",
            "required",
        )
        self.assertEqual(findings[0].status, "pass")
        self.assertEqual(findings[1].status, "pass")

    def test_reporting_endpoint_query_is_redacted_from_evidence(self):
        findings = analyze_reporting_readiness(
            {
                "reporting-endpoints": (
                    'csp="https://reports.example.test/csp?token=fixture-secret"'
                ),
                "content-security-policy": "default-src 'self'; report-to csp",
            },
            "https://example.test/app",
            "required",
        )
        self.assertNotIn("fixture-secret", findings[0].value or "")
        self.assertIn("<redacted>", findings[0].value or "")

    def test_reporting_endpoint_embedded_credentials_are_rejected(self):
        findings = analyze_reporting_readiness(
            {
                "reporting-endpoints": (
                    'csp="https://collector-user:collector-secret@'
                    'reports.example.test/csp"'
                ),
                "content-security-policy": "default-src 'self'; report-to csp",
            },
            "https://example.test/app",
            "required",
        )
        self.assertEqual(findings[0].status, "warning")
        self.assertNotIn("collector-secret", findings[0].value or "")

    def test_duplicate_legacy_reporting_groups_are_rejected(self):
        findings = analyze_reporting_readiness(
            {
                "report-to": json.dumps(
                    [
                        {
                            "group": "csp",
                            "max_age": 3600,
                            "endpoints": [{"url": "https://one.example.test/csp"}],
                        },
                        {
                            "group": "csp",
                            "max_age": 3600,
                            "endpoints": [{"url": "https://two.example.test/csp"}],
                        },
                    ]
                )
            },
            "https://example.test/app",
            "required",
        )
        self.assertEqual(findings[0].status, "warning")
        self.assertIn("Duplicate", findings[0].note)


class CrossOriginIsolationTests(unittest.TestCase):
    def test_complete_response_level_bundle_passes(self):
        fixture = load_fixture("assurance_ready")
        finding = analyze_cross_origin_isolation(
            {key.lower(): value for key, value in fixture["headers"].items()},
            "required",
        )
        self.assertEqual(finding.status, "pass")
        self.assertIn("unverified", finding.note)

    def test_partial_bundle_requires_review(self):
        finding = analyze_cross_origin_isolation(
            {
                "cross-origin-opener-policy": "same-origin-allow-popups",
                "cross-origin-resource-policy": "same-origin",
            },
            "recommended",
        )
        self.assertEqual(finding.status, "review")
        self.assertEqual(finding.severity, "medium")

    def test_missing_required_bundle_is_high_severity(self):
        finding = analyze_cross_origin_isolation({}, "required")
        self.assertEqual(finding.status, "missing")
        self.assertEqual(finding.severity, "high")

    def test_invalid_bundle_value_is_not_treated_as_ready(self):
        finding = analyze_cross_origin_isolation(
            {
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-embedder-policy": "require-corp",
                "cross-origin-resource-policy": "invalid",
            },
            "required",
        )
        self.assertEqual(finding.status, "warning")
        self.assertEqual(finding.severity, "high")
        self.assertIn("CORP value is invalid", finding.note)


class PolicyContractTests(unittest.TestCase):
    def test_v0_6_tool_exposes_v0_5_methodology_contract(self):
        self.assertEqual(__version__, "0.6.0")
        self.assertEqual(METHODOLOGY_VERSION, "0.5.0")
        policy = parse_policy(policy_payload())
        run = run_assurance(
            policy,
            audit_function=audit_from_fixture("assurance_ready"),
        )
        self.assertEqual(policy.methodology_version, METHODOLOGY_VERSION)
        self.assertEqual(run.methodology_version, METHODOLOGY_VERSION)

    def test_continuous_policy_requires_explicit_profile_by_default(self):
        payload = policy_payload(profile="auto")
        with self.assertRaisesRegex(PolicyConfigurationError, "explicit profile"):
            parse_policy(payload)

    def test_v0_4_policy_requires_explicit_migration_to_v0_5_methodology(self):
        payload = policy_payload()
        payload["methodology_version"] = "0.4.0"
        with self.assertRaisesRegex(PolicyConfigurationError, "does not match"):
            parse_policy(payload)

    def test_unknown_policy_fields_are_rejected(self):
        payload = policy_payload()
        payload["targets"][0]["minimun_score"] = 50
        with self.assertRaisesRegex(PolicyConfigurationError, "Unknown"):
            parse_policy(payload)

    def test_incompatible_policy_methodology_is_rejected(self):
        payload = policy_payload()
        payload["methodology_version"] = "9.9.9"
        with self.assertRaisesRegex(PolicyConfigurationError, "does not match"):
            parse_policy(payload)

    def test_unknown_required_control_is_rejected(self):
        payload = policy_payload(required_controls=["invented-control"])
        with self.assertRaisesRegex(PolicyConfigurationError, "Unknown required"):
            parse_policy(payload)

    def test_ready_fixture_passes_policy(self):
        policy = parse_policy(policy_payload())
        run = run_assurance(
            policy,
            audit_function=audit_from_fixture("assurance_ready"),
        )
        self.assertEqual(run.outcome, "passed")
        self.assertEqual(run.exit_code, 0)
        self.assertFalse(run.policy_violations)
        self.assertFalse(run.operational_errors)

    def test_broken_fixture_fails_policy(self):
        policy = parse_policy(policy_payload())
        run = run_assurance(
            policy,
            audit_function=audit_from_fixture("assurance_broken"),
        )
        self.assertEqual(run.outcome, "failed")
        self.assertEqual(run.exit_code, 1)
        codes = {violation.code for violation in run.policy_violations}
        self.assertIn("score.below_minimum", codes)
        self.assertIn("assurance.required_not_ready", codes)


class BaselineRegressionTests(unittest.TestCase):
    def setUp(self):
        self.policy = parse_policy(policy_payload())
        self.approved_run = run_assurance(
            self.policy,
            audit_function=audit_from_fixture("assurance_ready"),
        )
        self.baseline = create_baseline(self.approved_run)

    def test_unchanged_run_has_no_regressions(self):
        current = run_assurance(
            self.policy,
            baseline=self.baseline,
            audit_function=audit_from_fixture("assurance_ready"),
        )
        self.assertFalse(current.regressions)
        self.assertEqual(current.exit_code, 0)

    def test_score_and_control_regressions_are_detected(self):
        current = run_assurance(
            self.policy,
            baseline=self.baseline,
            audit_function=audit_from_fixture("assurance_broken"),
        )
        codes = {regression.code for regression in current.regressions}
        self.assertIn("score.regressed", codes)
        self.assertIn("control.status_regressed", codes)
        self.assertEqual(current.exit_code, 1)

    def test_unapproved_target_fails_regression_gate(self):
        baseline = dict(self.baseline)
        baseline["targets"] = {}
        current_run = run_assurance(
            self.policy,
            audit_function=audit_from_fixture("assurance_ready"),
        )
        regressions = compare_baseline(current_run.assessments, baseline)
        self.assertEqual(regressions[0].code, "baseline.unapproved_target")

    def test_target_url_change_and_orphaned_target_are_detected(self):
        changed_policy = parse_policy(
            policy_payload(url="https://secure.example.test/new-path")
        )
        current = run_assurance(
            changed_policy,
            audit_function=audit_from_fixture("assurance_ready"),
        )
        baseline = deepcopy(self.baseline)
        baseline["targets"]["retired-target"] = deepcopy(
            baseline["targets"]["secure-portal"]
        )
        regressions = compare_baseline(current.assessments, baseline)
        codes = {regression.code for regression in regressions}
        self.assertIn("target.changed", codes)
        self.assertIn("baseline.orphaned_target", codes)

    def test_selected_profile_change_is_detected(self):
        changed_policy = parse_policy(policy_payload(profile="brochure"))
        current = run_assurance(
            changed_policy,
            audit_function=audit_from_fixture("assurance_ready"),
        )
        regressions = compare_baseline(current.assessments, self.baseline)
        self.assertIn(
            "profile.changed",
            {regression.code for regression in regressions},
        )

    def test_new_actionable_finding_is_detected(self):
        baseline = deepcopy(self.baseline)
        del baseline["targets"]["secure-portal"]["findings"]["x-frame-options"]
        current = run_assurance(
            self.policy,
            baseline=baseline,
            audit_function=audit_from_fixture("assurance_broken"),
        )
        self.assertIn(
            "control.new_actionable_finding",
            {regression.code for regression in current.regressions},
        )

    def test_severity_regression_is_detected_without_status_change(self):
        relaxed_policy = parse_policy(
            policy_payload(
                minimum_score=0,
                fail_on_severity=[],
                required_controls=[],
                reporting_readiness="observe",
                cross_origin_isolation="observe",
            )
        )
        broken_run = run_assurance(
            relaxed_policy,
            audit_function=audit_from_fixture("assurance_broken"),
        )
        baseline = create_baseline(broken_run)
        hsts = baseline["targets"]["secure-portal"]["findings"][
            "strict-transport-security"
        ]
        hsts["severity"] = "low"
        hsts["points"] = 5.0
        regressions = compare_baseline(broken_run.assessments, baseline)
        self.assertIn(
            "control.severity_regressed",
            {regression.code for regression in regressions},
        )

    def test_points_regression_is_detected_without_status_or_severity_change(self):
        relaxed_policy = parse_policy(
            policy_payload(
                minimum_score=0,
                fail_on_severity=[],
                required_controls=[],
                reporting_readiness="observe",
                cross_origin_isolation="observe",
            )
        )
        broken_run = run_assurance(
            relaxed_policy,
            audit_function=audit_from_fixture("assurance_broken"),
        )
        baseline = create_baseline(broken_run)
        hsts = baseline["targets"]["secure-portal"]["findings"][
            "strict-transport-security"
        ]
        hsts["points"] = 15.0
        regressions = compare_baseline(broken_run.assessments, baseline)
        self.assertIn(
            "control.points_regressed",
            {regression.code for regression in regressions},
        )

    def test_methodology_change_requires_explicit_rebaseline(self):
        baseline = dict(self.baseline)
        baseline["methodology_version"] = "0.3.0"
        with self.assertRaisesRegex(BaselineCompatibilityError, "new approved baseline"):
            validate_baseline(baseline)

    def test_baseline_is_deterministic_and_contains_no_runtime_timestamp(self):
        first = json.dumps(self.baseline, sort_keys=True)
        second = json.dumps(create_baseline(self.approved_run), sort_keys=True)
        self.assertEqual(first, second)
        self.assertNotIn("generated_at", self.baseline)

    def test_failed_policy_run_cannot_be_baselined(self):
        failed = run_assurance(
            self.policy,
            audit_function=audit_from_fixture("assurance_broken"),
        )
        with self.assertRaisesRegex(BaselineCompatibilityError, "passing assurance"):
            create_baseline(failed)

    def test_baseline_rejects_unknown_enums_and_impossible_points(self):
        invalid_status = deepcopy(self.baseline)
        invalid_status["targets"]["secure-portal"]["findings"][
            "content-security-policy"
        ]["status"] = "probably-fine"
        with self.assertRaisesRegex(BaselineCompatibilityError, "unknown status"):
            validate_baseline(invalid_status)

        invalid_points = deepcopy(self.baseline)
        invalid_points["targets"]["secure-portal"]["findings"][
            "content-security-policy"
        ]["points"] = 26
        with self.assertRaisesRegex(BaselineCompatibilityError, "above max_points"):
            validate_baseline(invalid_points)

    def test_v0_4_baseline_requires_explicit_rebaseline_for_v0_5_methodology(self):
        legacy = dict(self.baseline)
        legacy["methodology_version"] = "0.4.0"
        with self.assertRaisesRegex(BaselineCompatibilityError, "new approved baseline"):
            validate_baseline(legacy)


class EvidenceMappingTests(unittest.TestCase):
    def test_manifest_is_versioned_and_evidence_only(self):
        self.assertEqual(MAPPING_SET_VERSION, "2026.07.2")
        self.assertEqual(
            MAPPING_MANIFEST.claims_policy,
            "supporting-evidence-only",
        )
        self.assertTrue(MAPPING_MANIFEST.mappings)

    def test_reporting_mapping_records_limitations(self):
        mappings = mappings_for_control("reporting-readiness")
        self.assertEqual(mappings[0].requirement, "V3.4.7")
        self.assertIn("does not prove", mappings[0].limitations)

    def test_csp_mappings_distinguish_evidence_families_and_confidence(self):
        mappings = mappings_for_control("content-security-policy")
        families = {mapping.evidence_family for mapping in mappings}
        self.assertIn("verification-requirement", families)
        self.assertIn("test-procedure", families)
        self.assertIn("security-control", families)
        self.assertIn("threat-mitigation", families)
        self.assertIn("defensive-technique", families)
        d3fend = next(
            mapping
            for mapping in mappings
            if mapping.framework_id == "mitre-d3fend"
        )
        self.assertEqual(d3fend.confidence, "inferred")
        self.assertIn("inferred relationship", d3fend.limitations)


class CurrentMethodologySchemaTests(unittest.TestCase):
    def test_current_policy_and_baseline_examples_validate_against_committed_schemas(self):
        root = Path(__file__).parents[1]
        cases = (
            (
                root / "docs" / "schemas" / "audit-policy.schema.json",
                root / "examples" / "ci-fixture-policy.json",
            ),
            (
                root / "docs" / "schemas" / "assurance-baseline.schema.json",
                root / "examples" / "ci-fixture-baseline.json",
            ),
        )
        for schema_path, example_path in cases:
            with self.subTest(example=example_path.name):
                schema = json.loads(schema_path.read_text(encoding="utf-8"))
                example = json.loads(example_path.read_text(encoding="utf-8"))
                Draft202012Validator.check_schema(schema)
                Draft202012Validator(schema).validate(example)
                self.assertEqual(example["methodology_version"], METHODOLOGY_VERSION)


class CIOutputTests(unittest.TestCase):
    def setUp(self):
        policy = parse_policy(policy_payload())
        approved = run_assurance(
            policy,
            audit_function=audit_from_fixture("assurance_ready"),
        )
        self.run = run_assurance(
            policy,
            baseline=create_baseline(approved),
            audit_function=audit_from_fixture("assurance_broken"),
        )

    def test_assurance_json_exposes_outcome_and_versions(self):
        payload = json.loads(render_assurance_json(self.run))
        self.assertEqual(payload["outcome"], "failed")
        self.assertEqual(payload["exit_code"], 1)
        self.assertEqual(payload["mapping_set_version"], "2026.07.2")

    def test_sarif_contains_regression_diagnostics(self):
        payload = json.loads(render_sarif(self.run))
        self.assertEqual(payload["version"], "2.1.0")
        results = payload["runs"][0]["results"]
        self.assertTrue(
            any(
                result["properties"]["diagnosticKind"] == "regression"
                for result in results
            )
        )

    def test_sarif_validates_against_official_oasis_schema(self):
        schema = json.loads(
            (
                Path(__file__).parent
                / "schemas"
                / "sarif-schema-2.1.0.json"
            ).read_text(encoding="utf-8")
        )
        Draft7Validator.check_schema(schema)
        Draft7Validator(schema).validate(json.loads(render_sarif(self.run)))

    def test_junit_contains_target_failure(self):
        root = fromstring(render_junit(self.run))
        self.assertEqual(root.tag, "testsuite")
        case = root.find("testcase")
        self.assertIsNotNone(case)
        failure = case.find("failure")
        self.assertIsNotNone(failure)
        self.assertIn("target=secure-portal", failure.text)
        self.assertIn("control=content-security-policy", failure.text)
        self.assertIn("previous='pass'; current='warning'", failure.text)

    def test_junit_exposes_baseline_only_target_regression(self):
        baseline = create_baseline(
            run_assurance(
                parse_policy(policy_payload()),
                audit_function=audit_from_fixture("assurance_ready"),
            )
        )
        baseline["targets"]["retired-target"] = deepcopy(
            baseline["targets"]["secure-portal"]
        )
        run = run_assurance(
            parse_policy(policy_payload()),
            baseline=baseline,
            audit_function=audit_from_fixture("assurance_ready"),
        )
        root = fromstring(render_junit(run))
        cases = {
            case.attrib["name"]: case
            for case in root.findall("testcase")
        }
        self.assertIn("retired-target", cases)
        failure = cases["retired-target"].find("failure")
        self.assertIsNotNone(failure)
        self.assertIn("baseline.orphaned_target", failure.text)

    def test_junit_distinguishes_operational_error(self):
        policy = parse_policy(policy_payload())
        ready_audit = audit_from_fixture("assurance_ready")

        def failing_audit(target: str, **kwargs):
            result = ready_audit(target, **kwargs)
            return replace(result, error="controlled fixture transport failure")

        run = run_assurance(policy, audit_function=failing_audit)
        root = fromstring(render_junit(run))
        case = root.find("testcase")
        self.assertIsNotNone(case)
        self.assertIsNotNone(case.find("error"))
        self.assertIsNone(case.find("failure"))
        self.assertEqual(root.attrib["errors"], "1")

    def test_human_reports_include_assurance_outcome(self):
        results = [assessment.result for assessment in self.run.assessments]
        markdown = render_markdown(results, assurance_run=self.run)
        html = render_html(results, assurance_run=self.run)
        self.assertIn("## Continuous Assurance", markdown)
        self.assertIn("score.regressed", markdown)
        self.assertIn('id="assurance-heading"', html)
        self.assertIn("Continuous Assurance", html)


if __name__ == "__main__":
    unittest.main()
