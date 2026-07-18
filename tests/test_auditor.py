import unittest
from unittest.mock import patch

from security_headers_auditor.auditor import audit_headers, normalize_target
from security_headers_auditor.report import render_markdown


class AuditorTests(unittest.TestCase):
    def test_normalize_target_adds_https(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com")

    def test_audit_headers_scores_present_headers(self):
        def fake_fetch_headers(target, timeout=8.0):
            return (
                "https://example.test",
                200,
                {
                    "Strict-Transport-Security": "max-age=31536000",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                },
            )

        with patch("security_headers_auditor.auditor.fetch_headers", fake_fetch_headers):
            result = audit_headers("https://example.test")

        self.assertIsNone(result.error)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.score, 35)
        self.assertEqual(result.summary, "Needs Review")
        self.assertTrue(
            any(finding.name == "Strict-Transport-Security" for finding in result.findings)
        )
        self.assertTrue(
            any(
                finding.name == "Content-Security-Policy"
                and finding.status == "missing"
                and finding.severity == "high"
                for finding in result.findings
            )
        )

    def test_audit_headers_warns_on_weak_values_and_disclosure(self):
        def fake_fetch_headers(target, timeout=8.0):
            return (
                "https://example.test",
                200,
                {
                    "Strict-Transport-Security": "max-age=300",
                    "Content-Security-Policy": "default-src *; script-src 'unsafe-inline'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "ALLOW-FROM https://legacy.example",
                    "Referrer-Policy": "unsafe-url",
                    "Permissions-Policy": "geolocation=*",
                    "Cross-Origin-Opener-Policy": "unsafe-none",
                    "Cross-Origin-Resource-Policy": "same-origin",
                    "Server": "Apache/2.4.6",
                    "X-Powered-By": "PHP/7.4",
                },
            )

        with patch("security_headers_auditor.auditor.fetch_headers", fake_fetch_headers):
            result = audit_headers("https://example.test")

        self.assertEqual(result.score, 58)
        warning_names = {
            finding.name
            for finding in result.findings
            if finding.status == "warning"
        }
        self.assertIn("Strict-Transport-Security", warning_names)
        self.assertIn("Content-Security-Policy", warning_names)
        self.assertIn("Referrer-Policy", warning_names)

        disclosure_names = {
            finding.name
            for finding in result.findings
            if finding.category == "disclosure"
        }
        self.assertEqual(disclosure_names, {"Server", "X-Powered-By"})

    def test_markdown_report_groups_findings(self):
        def fake_fetch_headers(target, timeout=8.0):
            return (
                "https://example.test",
                200,
                {
                    "X-Content-Type-Options": "nosniff",
                    "Server": "Apache/2.4.6",
                },
            )

        with patch("security_headers_auditor.auditor.fetch_headers", fake_fetch_headers):
            result = audit_headers("https://example.test")

        report = render_markdown([result])

        self.assertIn("## Executive Summary", report)
        self.assertIn("### Baseline Findings", report)
        self.assertIn("### Contextual Checks", report)
        self.assertIn("### Information-Disclosure Observations", report)
        self.assertIn("A strong score does not prove", report)


if __name__ == "__main__":
    unittest.main()
