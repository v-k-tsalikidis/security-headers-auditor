import unittest
from unittest.mock import patch

from security_headers_auditor.auditor import audit_headers, normalize_target


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
        self.assertEqual(result.score, 43)
        self.assertEqual(result.summary, "Needs Review")
        self.assertTrue(
            any(finding.name == "Strict-Transport-Security" for finding in result.findings)
        )


if __name__ == "__main__":
    unittest.main()

