from __future__ import annotations

import json
import unittest
from contextlib import redirect_stderr
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from unittest.mock import patch
from urllib.parse import urlparse

from jsonschema import Draft202012Validator

from security_headers_auditor.auditor import audit_headers
from security_headers_auditor.cli import main
from security_headers_auditor.route_comparison import (
    MAX_ROUTE_COUNT,
    RouteBaselineCompatibilityError,
    RouteComparisonConfigurationError,
    create_route_baseline,
    compare_route_baseline,
    parse_route_comparison,
    render_route_assurance_json,
    render_route_comparison_json,
    route_assurance_dict,
    route_comparison_dict,
    run_route_assurance,
    run_route_comparison,
    validate_route_baseline,
    write_route_baseline,
)


FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / f"{name}_headers.json").read_text(encoding="utf-8"))


def route_audit(routes: dict[str, dict[str, object]]):
    def audit(target: str, **kwargs):
        route = urlparse(target).path
        source = routes[route]
        headers = dict(source["headers"])

        def fetch(
            fetched_target: str,
            timeout: float = 8.0,
            allow_cross_origin_redirects: bool = False,
        ):
            del fetched_target, timeout, allow_cross_origin_redirects
            return target, int(source["status_code"]), headers

        with patch("security_headers_auditor.auditor.fetch_headers", fetch):
            return audit_headers(target, **kwargs)

    return audit


def comparison_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "name": "fixture portal routes",
        "origin": "https://portal.example.test",
        "routes": [
            {"id": "dashboard", "path": "/dashboard", "profile": "app"},
            {"id": "settings", "path": "/settings", "profile": "app"},
            {"id": "status", "path": "/api/status", "profile": "api"},
        ],
    }


class RouteComparisonConfigTests(unittest.TestCase):
    def test_manifest_schema_and_parser_accept_bounded_same_origin_routes(self):
        payload = comparison_payload()
        schema = json.loads(
            (
                Path(__file__).parents[1]
                / "docs"
                / "schemas"
                / "route-comparison.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(payload)

        config = parse_route_comparison(payload)
        self.assertEqual(config.origin, "https://portal.example.test")
        self.assertEqual(
            [route.url for route in config.routes],
            [
                "https://portal.example.test/dashboard",
                "https://portal.example.test/settings",
                "https://portal.example.test/api/status",
            ],
        )

    def test_manifest_rejects_scope_expansion_and_invalid_profiles_before_run(self):
        invalid_payloads = (
            {**comparison_payload(), "origin": "https://portal.example.test/base"},
            {
                **comparison_payload(),
                "routes": [
                    {"id": "dashboard", "path": "/dashboard", "profile": "app"},
                    {"id": "dashboard", "path": "/settings", "profile": "app"},
                ],
            },
            {
                **comparison_payload(),
                "routes": [
                    {"id": "dashboard", "path": "/dashboard", "profile": "app"},
                    {"id": "settings", "path": "/dashboard", "profile": "app"},
                ],
            },
            {
                **comparison_payload(),
                "routes": [
                    {"id": "dashboard", "path": "//other.example.test", "profile": "app"},
                    {"id": "settings", "path": "/settings", "profile": "app"},
                ],
            },
            {
                **comparison_payload(),
                "routes": [
                    {"id": "dashboard", "path": "/dashboard?token=secret", "profile": "app"},
                    {"id": "settings", "path": "/settings", "profile": "app"},
                ],
            },
            {
                **comparison_payload(),
                "routes": [
                    {"id": "dashboard", "path": "/dashboard?", "profile": "app"},
                    {"id": "settings", "path": "/settings", "profile": "app"},
                ],
            },
            {
                **comparison_payload(),
                "routes": [
                    {"id": "dashboard", "path": "/dashboard", "profile": "auto"},
                    {"id": "settings", "path": "/settings", "profile": "app"},
                ],
            },
            {
                **comparison_payload(),
                "routes": [
                    {"id": f"route-{index}", "path": f"/route-{index}", "profile": "app"}
                    for index in range(MAX_ROUTE_COUNT + 1)
                ],
            },
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(RouteComparisonConfigurationError):
                    parse_route_comparison(payload)


class RouteComparisonRunTests(unittest.TestCase):
    def setUp(self):
        strong_app = fixture("app")
        weak_app = fixture("app")
        weak_headers = dict(weak_app["headers"])
        weak_headers.pop("Content-Security-Policy")
        weak_app = {**weak_app, "headers": weak_headers}
        self.config = parse_route_comparison(comparison_payload())
        self.audit = route_audit(
            {
                "/dashboard": strong_app,
                "/settings": weak_app,
                "/api/status": fixture("api"),
            }
        )

    def test_run_requests_exact_declared_routes_and_finds_profile_control_variance(self):
        requested: list[tuple[str, dict[str, object]]] = []

        def recording_audit(target: str, **kwargs):
            requested.append((target, kwargs))
            return self.audit(target, **kwargs)

        run = run_route_comparison(self.config, audit_function=recording_audit)

        self.assertEqual(
            [target for target, _ in requested],
            [route.url for route in self.config.routes],
        )
        for _, kwargs in requested:
            self.assertFalse(kwargs["allow_cross_origin_redirects"])
            self.assertFalse(kwargs["include_query"])
        self.assertEqual(run.exit_code, 0)
        self.assertTrue(
            any(
                variance.profile.value == "app"
                and variance.control_key == "content-security-policy"
                for variance in run.variances
            )
        )
        self.assertFalse(any(variance.profile.value == "api" for variance in run.variances))

    def test_output_is_deterministic_and_omits_raw_header_values(self):
        run = run_route_comparison(self.config, audit_function=self.audit)
        first = render_route_comparison_json(run)
        second = render_route_comparison_json(run)
        payload = route_comparison_dict(run)

        self.assertEqual(first, second)
        self.assertEqual(payload["artifact"], "security-headers-auditor.route-comparison")
        self.assertNotIn("fixture-value", first)
        self.assertNotIn("default-src 'self'", first)
        self.assertIn("Content-Security-Policy", first)
        self.assertNotIn("generated_at", payload)
        self.assertTrue(payload["limitations"])

    def test_operational_errors_are_reported_without_turning_variance_into_failure(self):
        def operational_error(target: str, **kwargs):
            result = self.audit(target, **kwargs)
            if urlparse(target).path == "/settings":
                return replace(
                    result,
                    final_url=None,
                    status_code=None,
                    score=0,
                    summary="Error",
                    findings=[],
                    error="fixture transport failure",
                )
            return result

        run = run_route_comparison(self.config, audit_function=operational_error)
        self.assertEqual(run.exit_code, 2)
        self.assertEqual(len(run.operational_errors), 1)
        self.assertNotIn(
            "content-security-policy",
            {variance.control_key for variance in run.variances},
        )


class RouteAssuranceTests(unittest.TestCase):
    def setUp(self):
        strong_app = fixture("app")
        weak_app = fixture("app")
        weak_headers = dict(weak_app["headers"])
        weak_headers.pop("Content-Security-Policy")
        weak_app = {**weak_app, "headers": weak_headers}
        self.config = parse_route_comparison(comparison_payload())
        self.strong_audit = route_audit(
            {
                "/dashboard": strong_app,
                "/settings": strong_app,
                "/api/status": fixture("api"),
            }
        )
        self.regressed_audit = route_audit(
            {
                "/dashboard": strong_app,
                "/settings": weak_app,
                "/api/status": fixture("api"),
            }
        )

    def test_candidate_baseline_and_matching_run_are_compact_and_deterministic(self):
        initial = run_route_comparison(self.config, audit_function=self.strong_audit)
        baseline = create_route_baseline(initial)
        validate_route_baseline(baseline)
        schema = json.loads(
            (
                Path(__file__).parents[1]
                / "docs"
                / "schemas"
                / "route-assurance-baseline.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(baseline)

        run = run_route_assurance(
            self.config,
            baseline=baseline,
            audit_function=self.strong_audit,
        )
        first = render_route_assurance_json(run)
        second = render_route_assurance_json(run)
        payload = route_assurance_dict(run)

        self.assertEqual(run.outcome, "passed")
        self.assertEqual(run.exit_code, 0)
        self.assertEqual(first, second)
        self.assertEqual(payload["artifact"], "security-headers-auditor.route-assurance")
        self.assertEqual(payload["route_assurance"]["baseline_schema_version"], "1.0")
        self.assertFalse(payload["route_assurance"]["regressions"])
        self.assertNotIn("fixture-value", first)
        self.assertNotIn("default-src 'self'", first)

    def test_regressed_score_and_control_fail_route_assurance_without_operational_error(self):
        baseline = create_route_baseline(
            run_route_comparison(self.config, audit_function=self.strong_audit)
        )
        run = run_route_assurance(
            self.config,
            baseline=baseline,
            audit_function=self.regressed_audit,
        )

        signals = {(item.code, item.control_key) for item in run.regressions}
        self.assertEqual(run.outcome, "failed")
        self.assertEqual(run.exit_code, 1)
        self.assertIn(("score.regressed", None), signals)
        self.assertIn(("control.status_regressed", "content-security-policy"), signals)
        self.assertFalse(run.comparison.operational_errors)

    def test_baseline_scope_or_version_tampering_is_rejected_before_comparison(self):
        baseline = create_route_baseline(
            run_route_comparison(self.config, audit_function=self.strong_audit)
        )
        tampered_version = {**baseline, "methodology_version": "future"}
        with self.assertRaises(RouteBaselineCompatibilityError):
            validate_route_baseline(tampered_version)

        tampered_scope = json.loads(json.dumps(baseline))
        tampered_scope["manifest"]["routes"][0]["path"] = "/other"
        with self.assertRaises(RouteBaselineCompatibilityError):
            compare_route_baseline(
                run_route_comparison(self.config, audit_function=self.strong_audit),
                tampered_scope,
            )

    def test_candidate_rejects_partial_run_and_never_overwrites_existing_path(self):
        def failing_audit(target: str, **kwargs):
            result = self.strong_audit(target, **kwargs)
            if urlparse(target).path == "/settings":
                return replace(result, findings=[], error="fixture transport failure")
            return result

        partial = run_route_comparison(self.config, audit_function=failing_audit)
        with self.assertRaises(RouteBaselineCompatibilityError):
            create_route_baseline(partial)

        complete = run_route_comparison(self.config, audit_function=self.strong_audit)
        with TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "candidate.json"
            write_route_baseline(path, complete)
            with self.assertRaises(RouteBaselineCompatibilityError):
                write_route_baseline(path, complete)


class RouteComparisonCliTests(unittest.TestCase):
    def test_cli_runs_only_declared_routes_against_loopback_fixture(self):
        fixtures = {
            "/app": fixture("app"),
            "/assurance-ready": fixture("assurance_ready"),
            "/api": fixture("api"),
        }

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):  # noqa: N802 - BaseHTTPRequestHandler API
                route_fixture = fixtures[self.path]
                self.send_response(int(route_fixture["status_code"]))
                for name, value in dict(route_fixture["headers"]).items():
                    self.send_header(str(name), str(value))
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                del format, args

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}"
            manifest_payload = {
                "schema_version": "1.0",
                "name": "loopback fixture comparison",
                "origin": origin,
                "routes": [
                    {"id": "app", "path": "/app", "profile": "app"},
                    {
                        "id": "assurance-ready",
                        "path": "/assurance-ready",
                        "profile": "app",
                    },
                    {"id": "api", "path": "/api", "profile": "api"},
                ],
            }
            with TemporaryDirectory() as temporary_directory:
                manifest = Path(temporary_directory) / "routes.json"
                output = Path(temporary_directory) / "comparison.json"
                manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
                self.assertEqual(
                    main(
                        [
                            "--route-comparison",
                            str(manifest),
                            "--format",
                            "json",
                            "--output",
                            str(output),
                        ]
                    ),
                    0,
                )
                payload = json.loads(output.read_text(encoding="utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual([route["id"] for route in payload["routes"]], ["app", "assurance-ready", "api"])
        self.assertFalse(payload["operational_errors"])

    def test_cli_writes_compact_json_report(self):
        config = parse_route_comparison(comparison_payload())
        fixture_audit = route_audit(
            {
                "/dashboard": fixture("app"),
                "/settings": fixture("app"),
                "/api/status": fixture("api"),
            }
        )
        run = run_route_assurance(config, audit_function=fixture_audit)
        with TemporaryDirectory() as temporary_directory:
            manifest = Path(temporary_directory) / "routes.json"
            output = Path(temporary_directory) / "comparison.json"
            manifest.write_text(json.dumps(comparison_payload()), encoding="utf-8")
            with patch(
                "security_headers_auditor.cli.run_route_assurance",
                return_value=run,
            ) as runner:
                self.assertEqual(
                    main(
                        [
                            "--route-comparison",
                            str(manifest),
                            "--format",
                            "json",
                            "--output",
                            str(output),
                        ]
                    ),
                    0,
                )
            runner.assert_called_once()
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["name"], "fixture portal routes")
            self.assertEqual(payload["artifact"], "security-headers-auditor.route-assurance")
            self.assertNotIn("fixture-value", output.read_text(encoding="utf-8"))

    def test_cli_writes_a_new_route_baseline_candidate_without_network_reuse(self):
        config = parse_route_comparison(comparison_payload())
        run = run_route_assurance(
            config,
            audit_function=route_audit(
                {
                    "/dashboard": fixture("app"),
                    "/settings": fixture("app"),
                    "/api/status": fixture("api"),
                }
            ),
        )
        with TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            manifest = directory / "routes.json"
            candidate = directory / "candidate.json"
            output = directory / "candidate-report.md"
            manifest.write_text(json.dumps(comparison_payload()), encoding="utf-8")
            with patch(
                "security_headers_auditor.cli.run_route_assurance",
                return_value=run,
            ) as runner:
                self.assertEqual(
                    main(
                        [
                            "--route-comparison",
                            str(manifest),
                            "--write-route-baseline",
                            str(candidate),
                            "--output",
                            str(output),
                        ]
                    ),
                    0,
                )
            runner.assert_called_once()
            baseline = json.loads(candidate.read_text(encoding="utf-8"))
            validate_route_baseline(baseline)
            self.assertNotIn("fixture-value", candidate.read_text(encoding="utf-8"))

    def test_invalid_manifest_returns_configuration_error_before_run(self):
        with TemporaryDirectory() as temporary_directory:
            manifest = Path(temporary_directory) / "invalid.json"
            manifest.write_text("{not json", encoding="utf-8")
            with patch("security_headers_auditor.cli.run_route_assurance") as run:
                with redirect_stderr(StringIO()):
                    self.assertEqual(main(["--route-comparison", str(manifest)]), 2)
            run.assert_not_called()

    def test_cli_rejects_ambiguous_audit_modes(self):
        with TemporaryDirectory() as temporary_directory:
            manifest = Path(temporary_directory) / "routes.json"
            manifest.write_text(json.dumps(comparison_payload()), encoding="utf-8")
            for arguments in (
                ["--route-comparison", str(manifest), "https://portal.example.test/"],
                ["--route-comparison", str(manifest), "--policy", "policy.json"],
                ["--route-comparison", str(manifest), "--profile", "app"],
                ["--route-comparison", str(manifest), "--format", "html"],
                [
                    "--route-comparison",
                    str(manifest),
                    "--route-baseline",
                    "baseline.json",
                    "--write-route-baseline",
                    "candidate.json",
                ],
            ):
                with self.subTest(arguments=arguments):
                    with redirect_stderr(StringIO()):
                        with self.assertRaises(SystemExit) as raised:
                            main(arguments)
                    self.assertEqual(raised.exception.code, 2)
