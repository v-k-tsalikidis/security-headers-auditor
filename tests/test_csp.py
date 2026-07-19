from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from security_headers_auditor.assurance_controls import analyze_reporting_readiness
from security_headers_auditor.auditor import audit_headers
from security_headers_auditor.csp import MAX_CSP_HEADER_LENGTH, parse_csp


FIXTURES = Path(__file__).parent / "fixtures"


def app_headers_with(csp: str) -> dict[str, str]:
    fixture = json.loads((FIXTURES / "app_headers.json").read_text(encoding="utf-8"))
    headers = dict(fixture["headers"])
    headers["Content-Security-Policy"] = csp
    return headers


def audit_csp(csp: str):
    headers = app_headers_with(csp)

    def fetch(
        target: str,
        timeout: float = 8.0,
        allow_cross_origin_redirects: bool = False,
    ):
        del target, timeout, allow_cross_origin_redirects
        return "https://portal.example.test/dashboard", 200, headers

    with patch("security_headers_auditor.auditor.fetch_headers", fetch):
        result = audit_headers("https://portal.example.test/dashboard")
    return next(finding for finding in result.findings if finding.key == "content-security-policy")


class CSPParserTests(unittest.TestCase):
    def test_first_duplicate_directive_is_retained_and_source_case_is_preserved(self):
        parsed = parse_csp(
            "script-src 'nonce-AbCdEf0123=='; SCRIPT-SRC data:; object-src 'none'"
        )

        policy = parsed.policies[0]
        self.assertEqual(
            policy.directive_values("script-src"),
            ("'nonce-AbCdEf0123=='",),
        )
        self.assertEqual(
            [issue.code for issue in policy.issues],
            ["duplicate_directive_ignored"],
        )
        self.assertEqual(policy.issues[0].directive_name, "script-src")

    def test_policy_list_and_invalid_directive_tokens_are_explicit(self):
        parsed = parse_csp(
            "default-src 'self'; report-to primary, default-src 'none'; report-to backup"
        )
        self.assertEqual(len(parsed.policies), 2)
        self.assertEqual(parsed.directive_values("report-to"), ("primary", "backup"))

        invalid = parse_csp("default-src 'self'; café-src 'none'; \x01bad value")
        self.assertEqual(
            {issue.code for issue in invalid.policies[0].issues},
            {"non_ascii_or_control_directive_ignored"},
        )


class CSPEvaluationTests(unittest.TestCase):
    def test_data_scheme_in_effective_script_sources_is_high_risk(self):
        finding = audit_csp(
            "default-src 'self'; script-src 'self' data:; object-src 'none'; base-uri 'none'"
        )
        self.assertEqual((finding.status, finding.severity, finding.points), ("warning", "high", 6.25))
        self.assertIn("data:", finding.note)

    def test_invalid_nonce_does_not_neutralize_unsafe_inline(self):
        finding = audit_csp(
            "default-src 'self'; script-src 'unsafe-inline' 'nonce-not*valid'; "
            "object-src 'none'; base-uri 'none'"
        )
        self.assertEqual((finding.status, finding.severity, finding.points), ("warning", "high", 10.0))
        self.assertIn("valid nonce or hash", finding.note)

    def test_valid_nonce_keeps_unsafe_inline_case_explicitly_limited(self):
        finding = audit_csp(
            "default-src 'self'; script-src 'unsafe-inline' 'nonce-AbCdEf0123=='; "
            "object-src 'none'; base-uri 'none'"
        )
        self.assertEqual((finding.status, finding.severity, finding.points), ("pass", "info", 25.0))
        self.assertIn("Verify nonce/hash lifecycle", finding.note)

    def test_duplicate_and_multiple_policy_cases_are_review_signals(self):
        duplicate = audit_csp(
            "default-src 'self'; script-src 'self'; script-src data:; "
            "object-src 'none'; base-uri 'none'"
        )
        self.assertEqual((duplicate.status, duplicate.severity, duplicate.points), ("warning", "medium", 18.75))
        self.assertIn("duplicate", duplicate.note.lower())

        multiple = audit_csp(
            "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none', "
            "default-src 'none'"
        )
        self.assertEqual((multiple.status, multiple.severity, multiple.points), ("warning", "medium", 18.75))
        self.assertIn("intersection", multiple.note)

    def test_csp_size_limit_is_bounded_and_visible(self):
        finding = audit_csp("default-src 'self';" + ("a" * MAX_CSP_HEADER_LENGTH))
        self.assertEqual((finding.status, finding.severity, finding.points), ("warning", "high", 6.25))
        self.assertIn("16 KiB", finding.note)


class CSPReportingLinkageTests(unittest.TestCase):
    def test_reporting_linkage_uses_first_duplicate_report_to_group(self):
        findings = analyze_reporting_readiness(
            {
                "reporting-endpoints": 'primary="https://collector.example.test/csp"',
                "content-security-policy": (
                    "default-src 'self'; REPORT-TO primary; report-to unlinked"
                ),
            },
            "https://portal.example.test/dashboard",
            "required",
        )
        self.assertEqual(findings[1].status, "pass")
        self.assertIn("modern reporting endpoint definitions", findings[1].note)
