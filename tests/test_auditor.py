from __future__ import annotations

import json
import re
import socket
import unittest
from contextlib import redirect_stderr
from email.message import Message
from io import BytesIO, StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from unittest.mock import patch

from jsonschema import Draft202012Validator

from security_headers_auditor.auditor import (
    TargetAddressBoundaryError,
    _redirect_is_allowed,
    _ensure_public_target,
    audit_headers,
    fetch_headers,
    normalize_target,
    redact_url,
)
from security_headers_auditor.cli import build_parser, main
from security_headers_auditor.catalog import CITATIONS, RULES
from security_headers_auditor.profile_export import (
    build_profile_definition_export,
    render_profile_definition_export,
)
from security_headers_auditor.profiles import (
    PROFILE_DEFINITIONS,
    ProfileName,
    resolve_profile,
)
from security_headers_auditor.report import render_html, render_json, render_markdown


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / f"{name}_headers.json").read_text(encoding="utf-8"))


def fixture_fetch(name: str):
    fixture = load_fixture(name)

    def fetch(
        target: str,
        timeout: float = 8.0,
        allow_cross_origin_redirects: bool = False,
    ):
        del target, timeout, allow_cross_origin_redirects
        return (
            fixture["final_url"],
            fixture["status_code"],
            fixture["headers"],
        )

    return fetch


class TargetHandlingTests(unittest.TestCase):
    def test_normalize_target_adds_https(self):
        self.assertEqual(normalize_target("example.com"), "https://example.com")

    def test_normalize_target_rejects_non_http_scheme(self):
        with self.assertRaisesRegex(ValueError, "Unsupported URL scheme"):
            normalize_target("file:///etc/passwd")

    def test_normalize_target_rejects_embedded_credentials(self):
        with self.assertRaisesRegex(ValueError, "Credentials"):
            normalize_target("https://user:secret@example.test")

    def test_url_query_and_fragment_are_redacted_by_default(self):
        self.assertEqual(
            redact_url("https://example.test/path?token=secret#account"),
            "https://example.test/path?<redacted>#<redacted>",
        )

    def test_url_query_and_fragment_can_be_retained_explicitly(self):
        url = "https://example.test/path?case=public#result"
        self.assertEqual(redact_url(url, include_query=True), url)

    def test_error_message_does_not_restore_redacted_url_data(self):
        result = audit_headers("https:///path?token=fixture-secret#private")
        self.assertEqual(result.summary, "Error")
        self.assertNotIn("fixture-secret", result.error or "")
        self.assertIn("<redacted>", result.error or "")

    def test_same_origin_and_http_to_https_redirects_are_allowed(self):
        self.assertTrue(
            _redirect_is_allowed(
                "https://example.test/start",
                "https://example.test/final",
            )
        )
        self.assertTrue(
            _redirect_is_allowed(
                "http://example.test/start",
                "https://example.test/final",
            )
        )

    def test_cross_origin_and_port_redirects_are_blocked(self):
        self.assertFalse(
            _redirect_is_allowed(
                "https://example.test/start",
                "https://other.example.test/final",
            )
        )

    def test_workspace_public_scope_rejects_non_global_addresses(self):
        for target in (
            "http://127.0.0.1/",
            "http://169.254.169.254/",
            "http://10.0.0.1/",
            "http://[::1]/",
        ):
            with self.subTest(target=target):
                with self.assertRaises(TargetAddressBoundaryError):
                    _ensure_public_target(target)

    def test_workspace_public_scope_accepts_resolved_global_address(self):
        with patch(
            "security_headers_auditor.auditor.socket.getaddrinfo",
            return_value=[
                (
                    2,
                    1,
                    6,
                    "",
                    ("93.184.216.34", 443),
                )
            ],
        ):
            _ensure_public_target("https://example.test/")

    def test_workspace_public_scope_revalidates_before_connection(self):
        global_resolution = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        ]
        rebinding_resolution = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ]
        with patch(
            "security_headers_auditor.auditor.socket.getaddrinfo",
            side_effect=[global_resolution, rebinding_resolution],
        ) as resolver:
            with self.assertRaises(TargetAddressBoundaryError):
                fetch_headers("https://example.test/", allow_private_targets=False)
        self.assertEqual(resolver.call_count, 2)
        self.assertFalse(
            _redirect_is_allowed(
                "https://example.test:8443/start",
                "https://example.test:9443/final",
            )
        )


class FetchPolicyTests(unittest.TestCase):
    class Response:
        def __init__(self, url: str, status: int, headers: dict[str, str]):
            self._url = url
            self.status = status
            self.headers = headers

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            del exc_type, exc_value, traceback

        def geturl(self) -> str:
            return self._url

    class Opener:
        def __init__(self, outcomes: list[object]):
            self.outcomes = outcomes
            self.methods: list[str] = []

        def open(self, request, timeout: float):
            del timeout
            self.methods.append(request.get_method())
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    @staticmethod
    def http_error(code: int) -> HTTPError:
        return HTTPError(
            "https://example.test/",
            code,
            "fixture error",
            Message(),
            BytesIO(),
        )

    def test_http_error_response_is_audited_without_get_retry(self):
        opener = self.Opener([self.http_error(404)])
        with patch(
            "security_headers_auditor.auditor.build_opener",
            return_value=opener,
        ):
            _, status, _ = fetch_headers("https://example.test/")

        self.assertEqual(status, 404)
        self.assertEqual(opener.methods, ["HEAD"])

    def test_get_fallback_is_limited_to_head_not_supported(self):
        opener = self.Opener(
            [
                self.http_error(405),
                self.Response(
                    "https://example.test/",
                    200,
                    {"Content-Type": "text/html"},
                ),
            ]
        )
        with patch(
            "security_headers_auditor.auditor.build_opener",
            return_value=opener,
        ):
            _, status, _ = fetch_headers("https://example.test/")

        self.assertEqual(status, 200)
        self.assertEqual(opener.methods, ["HEAD", "GET"])


class ProfileEngineTests(unittest.TestCase):
    def test_every_profile_weight_total_is_100(self):
        for profile in PROFILE_DEFINITIONS.values():
            with self.subTest(profile=profile.name.value):
                self.assertEqual(
                    sum(policy.weight for policy in profile.policies.values()),
                    100,
                )

    def test_auto_detects_machine_readable_response_as_api(self):
        decision = resolve_profile("auto", {"content-type": "application/problem+json"})
        self.assertEqual(decision.selected, ProfileName.API)
        self.assertEqual(decision.confidence, "high")

    def test_auto_requires_multiple_application_signals(self):
        decision = resolve_profile(
            "auto",
            {
                "content-type": "text/html",
                "set-cookie": "session=value",
                "cache-control": "private, no-store",
            },
        )
        self.assertEqual(decision.selected, ProfileName.APP)
        self.assertEqual(decision.confidence, "medium")

    def test_auto_defaults_plain_html_to_brochure(self):
        decision = resolve_profile("auto", {"content-type": "text/html"})
        self.assertEqual(decision.selected, ProfileName.BROCHURE)
        self.assertEqual(decision.confidence, "medium")

    def test_auto_uses_low_confidence_fallback_for_ambiguous_response(self):
        decision = resolve_profile("auto", {})
        self.assertEqual(decision.selected, ProfileName.BROCHURE)
        self.assertEqual(decision.confidence, "low")

    def test_manual_profile_override_is_explicit(self):
        decision = resolve_profile("app", {"content-type": "application/json"})
        self.assertEqual(decision.selected, ProfileName.APP)
        self.assertEqual(decision.confidence, "explicit")
        self.assertTrue(decision.manual_override)

    def test_catalog_profiles_and_citations_are_complete(self):
        rule_keys = {rule.key for rule in RULES}
        self.assertEqual(len(rule_keys), len(RULES))
        for profile in PROFILE_DEFINITIONS.values():
            self.assertEqual(set(profile.policies), rule_keys)
        for rule in RULES:
            with self.subTest(rule=rule.key):
                self.assertTrue(rule.citation_keys)
                self.assertTrue(set(rule.citation_keys).issubset(CITATIONS))
        for citation in CITATIONS.values():
            with self.subTest(citation=citation.key):
                self.assertRegex(citation.url, r"^https?://")


class ProfileDefinitionExportTests(unittest.TestCase):
    def test_export_is_deterministic_complete_and_static(self):
        first = render_profile_definition_export()
        second = render_profile_definition_export()
        payload = json.loads(first)

        self.assertEqual(first, second)
        self.assertTrue(first.endswith("\n"))
        self.assertEqual(
            [profile["id"] for profile in payload["profiles"]],
            [profile.value for profile in ProfileName],
        )
        self.assertNotIn("generated_at", payload)
        self.assertTrue(payload["limitations"])
        self.assertEqual(payload["evidence_claims_policy"], "supporting-evidence-only")

        rule_keys = [rule.key for rule in RULES]
        citation_keys = {citation["key"] for citation in payload["citations"]}
        self.assertEqual(len(citation_keys), len(payload["citations"]))
        for profile in payload["profiles"]:
            with self.subTest(profile=profile["id"]):
                self.assertEqual(profile["scored_weight_total"], 100)
                self.assertEqual(
                    [control["key"] for control in profile["controls"]],
                    rule_keys,
                )
                self.assertEqual(
                    sum(control["score_weight"] for control in profile["controls"]),
                    100,
                )
                for control in profile["controls"]:
                    self.assertTrue(set(control["citation_keys"]).issubset(citation_keys))
                    self.assertTrue(
                        {
                            mapping["citation_key"]
                            for mapping in control["supporting_evidence_mappings"]
                        }.issubset(citation_keys)
                    )

    def test_export_validates_against_committed_schema(self):
        schema = json.loads(
            (
                Path(__file__).parents[1]
                / "docs"
                / "schemas"
                / "profile-definitions.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(build_profile_definition_export())

    def test_cli_export_never_invokes_audit_or_network_path(self):
        with TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "profiles.json"
            with patch("security_headers_auditor.cli.audit_headers") as audit:
                exit_code = main(
                    ["--export-profile-definitions", str(output_path)]
                )

            self.assertEqual(exit_code, 0)
            audit.assert_not_called()
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(
                payload["artifact"],
                "security-headers-auditor.profile-definitions",
            )

    def test_cli_export_rejects_audit_or_report_inputs(self):
        with TemporaryDirectory() as temporary_directory:
            output_path = Path(temporary_directory) / "profiles.json"
            for arguments in (
                ["https://example.test", "--export-profile-definitions", str(output_path)],
                ["--export-profile-definitions", str(output_path), "--policy", "policy.json"],
                ["--export-profile-definitions", str(output_path), "--output", "report.json"],
                ["--export-profile-definitions", str(output_path), "--format", "json"],
                ["--export-profile-definitions", str(output_path), "--format", "markdown"],
            ):
                with self.subTest(arguments=arguments):
                    with redirect_stderr(StringIO()):
                        with self.assertRaises(SystemExit) as raised:
                            main(arguments)
                    self.assertEqual(raised.exception.code, 2)


class ProfileAwareAuditTests(unittest.TestCase):
    def test_api_fixture_has_stable_score_and_does_not_score_csp(self):
        with patch(
            "security_headers_auditor.auditor.fetch_headers",
            fixture_fetch("api"),
        ):
            result = audit_headers("https://api.example.test/v1/status")

        self.assertEqual(result.selected_profile, "api")
        self.assertEqual(result.score, 100)
        csp = next(
            finding
            for finding in result.findings
            if finding.key == "content-security-policy"
        )
        self.assertEqual(csp.category, "contextual")
        self.assertEqual(csp.max_points, 0)
        self.assertEqual(csp.status, "info")

    def test_application_fixture_has_stable_score(self):
        with patch(
            "security_headers_auditor.auditor.fetch_headers",
            fixture_fetch("app"),
        ):
            result = audit_headers("https://portal.example.test/dashboard")

        self.assertEqual(result.selected_profile, "app")
        self.assertEqual(result.score, 100)
        self.assertEqual(result.summary, "Strong")

    def test_csp_frame_ancestors_satisfies_framing_control(self):
        with patch(
            "security_headers_auditor.auditor.fetch_headers",
            fixture_fetch("app"),
        ):
            result = audit_headers("https://portal.example.test/dashboard")

        xfo = next(
            finding
            for finding in result.findings
            if finding.key == "x-frame-options"
        )
        self.assertEqual(xfo.status, "pass")
        self.assertEqual(xfo.points, xfo.max_points)
        self.assertIn("frame-ancestors", xfo.note)

    def test_csp_without_script_restriction_is_high_severity_warning(self):
        fixture = load_fixture("app")
        headers = dict(fixture["headers"])
        headers["Content-Security-Policy"] = "frame-ancestors 'self'"

        def fetch(
            target: str,
            timeout: float = 8.0,
            allow_cross_origin_redirects: bool = False,
        ):
            del target, timeout, allow_cross_origin_redirects
            return fixture["final_url"], fixture["status_code"], headers

        with patch("security_headers_auditor.auditor.fetch_headers", fetch):
            result = audit_headers("https://portal.example.test/dashboard")

        csp = next(
            finding
            for finding in result.findings
            if finding.key == "content-security-policy"
        )
        self.assertEqual(csp.status, "warning")
        self.assertEqual(csp.severity, "high")
        self.assertEqual(csp.points, 6.25)
        self.assertIn("script-src", csp.note)

    def test_brochure_fixture_preserves_expected_warning_and_score(self):
        with patch(
            "security_headers_auditor.auditor.fetch_headers",
            fixture_fetch("brochure"),
        ):
            result = audit_headers("https://www.example.test/")

        self.assertEqual(result.selected_profile, "brochure")
        self.assertEqual(result.score, 82)
        csp = next(
            finding
            for finding in result.findings
            if finding.key == "content-security-policy"
        )
        self.assertEqual(csp.status, "warning")
        self.assertEqual(csp.severity, "high")

    def test_manual_app_override_changes_api_applicability_and_score(self):
        with patch(
            "security_headers_auditor.auditor.fetch_headers",
            fixture_fetch("api"),
        ):
            automatic = audit_headers("https://api.example.test/v1/status")
            overridden = audit_headers(
                "https://api.example.test/v1/status",
                profile="app",
            )

        self.assertEqual(automatic.score, 100)
        self.assertEqual(overridden.selected_profile, "app")
        self.assertEqual(overridden.profile_confidence, "explicit")
        self.assertEqual(overridden.score, 30)

    def test_report_redacts_final_url_by_default(self):
        with patch(
            "security_headers_auditor.auditor.fetch_headers",
            fixture_fetch("hostile"),
        ):
            result = audit_headers(
                "https://hostile.example.test/?token=fixture-secret#private"
            )

        self.assertNotIn("fixture-secret", result.target)
        self.assertNotIn("fixture-secret", result.final_url or "")


class ReportRegressionTests(unittest.TestCase):
    def _result(self, name: str):
        with patch(
            "security_headers_auditor.auditor.fetch_headers",
            fixture_fetch(name),
        ):
            return audit_headers(f"https://{name}.example.test/")

    def test_markdown_report_records_profile_and_research(self):
        report = render_markdown([self._result("brochure")])
        self.assertIn("Methodology version: `0.4.0`", report)
        self.assertIn("Evidence mapping set: `2026.07.2`", report)
        self.assertIn("### Assurance Controls", report)
        self.assertIn("### Profile Decision", report)
        self.assertIn(
            "OWASP Application Security Verification Standard 5.0.0",
            report,
        )
        self.assertIn("not evidence of compromise", report)

    def test_json_report_exposes_methodology_and_profile(self):
        payload = json.loads(render_json([self._result("api")]))
        self.assertEqual(payload["methodology_version"], "0.4.0")
        self.assertEqual(payload["mapping_set_version"], "2026.07.2")
        self.assertEqual(payload["results"][0]["selected_profile"], "api")
        self.assertEqual(payload["results"][0]["score"], 100)

    def test_reports_do_not_make_compliance_or_certification_claims(self):
        result = self._result("app")
        markdown = render_markdown([result]).lower()
        html = render_html([result]).lower()
        report_json = render_json([result]).lower()

        for rendered in (markdown, html, report_json):
            self.assertNotIn("compliant", rendered)
            self.assertNotIn("certified", rendered)

        self.assertIn("not evidence of compromise or regulatory compliance", markdown)
        self.assertIn("not compliance certification", html)

    def test_html_report_is_self_contained_and_script_free(self):
        html = render_html([self._result("app")])
        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertIn('id="main-content"', html)
        self.assertIn("<details", html)
        self.assertIn('id="target-1-result"', html)
        self.assertIn('data-finding-key="content-security-policy"', html)
        self.assertIn("Content-Security-Policy", html)
        self.assertNotRegex(html.lower(), r"<script(?:\s|>)")
        self.assertNotRegex(html.lower(), r"<link(?:\s|>)")
        self.assertNotRegex(html.lower(), r'src="https?://')
        self.assertIn('rel="noopener noreferrer"', html)

    def test_html_escapes_untrusted_header_values(self):
        html = render_html([self._result("hostile")])
        self.assertNotIn("<script>alert('server')</script>", html)
        self.assertNotIn("<img src=x onerror=alert('framework')>", html)
        self.assertIn("&lt;script&gt;alert(&#x27;server&#x27;)&lt;/script&gt;", html)
        self.assertIn("&lt;img src=x onerror=alert(&#x27;framework&#x27;)&gt;", html)

    def test_markdown_escapes_untrusted_header_values(self):
        markdown = render_markdown([self._result("hostile")])
        self.assertNotIn("<script>alert('server')</script>", markdown)
        self.assertNotIn("<img src=x onerror=alert('framework')>", markdown)
        self.assertIn("&lt;script&gt;alert('server')&lt;/script&gt;", markdown)
        self.assertIn(
            "&lt;img src=x onerror=alert('framework')&gt;",
            markdown,
        )

    def test_cli_exposes_profile_html_and_privacy_controls(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "example.test",
                "--profile",
                "api",
                "--format",
                "html",
                "--include-query",
                "--allow-cross-origin-redirects",
                "--reporting-readiness",
                "required",
                "--cross-origin-isolation",
                "recommended",
            ]
        )
        self.assertEqual(args.profile, "api")
        self.assertEqual(args.format, "html")
        self.assertTrue(args.include_query)
        self.assertTrue(args.allow_cross_origin_redirects)
        self.assertEqual(args.reporting_readiness, "required")
        self.assertEqual(args.cross_origin_isolation, "recommended")

    def test_html_contains_no_remote_runtime_dependencies(self):
        html = render_html([self._result("app")])
        self.assertNotIn("@import", html)
        self.assertNotIn("url(http", html.lower())
        self.assertFalse(
            re.search(r'<(?:img|iframe|script)[^>]+src=["\']', html, re.IGNORECASE)
        )

    def test_html_accessibility_contract_is_present(self):
        html = render_html([self._result("app")])
        self.assertIn('<html lang="en">', html)
        self.assertIn('class="skip-link"', html)
        self.assertIn("<progress", html)
        self.assertIn("<summary>", html)
        self.assertIn('class="table-scroll" tabindex="0"', html)
        self.assertIn("@media (prefers-reduced-motion: reduce)", html)
        self.assertIn("focus-visible", html)


if __name__ == "__main__":
    unittest.main()
