"""Command-line interface for Security Headers Auditor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .assurance import (
    BaselineCompatibilityError,
    PolicyConfigurationError,
    load_baseline,
    load_policy,
    run_assurance,
    write_baseline,
)
from .auditor import audit_headers
from .ci_report import (
    render_assurance_json,
    render_assurance_review_json,
    render_junit,
    render_sarif,
)
from .evidence_capsule import (
    EvidenceCapsuleError,
    create_evidence_capsule,
    verify_evidence_capsule,
)
from .profile_export import render_profile_definition_export
from .report import render_html, render_json, render_markdown
from .route_comparison import (
    RouteBaselineCompatibilityError,
    RouteComparisonConfigurationError,
    load_route_baseline,
    load_route_comparison,
    render_route_assurance_json,
    render_route_assurance_markdown,
    render_route_assurance_review_json,
    run_route_assurance,
    write_route_baseline,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only HTTP security headers auditor for user-provided targets."
    )
    parser.add_argument("targets", nargs="*", help="Target URLs or hostnames to audit.")
    parser.add_argument(
        "--input-file",
        type=Path,
        help="Plain text file containing one target per line.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json", "review-json", "html", "sarif", "junit"),
        default="markdown",
        help="Report output format.",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        help=(
            "Run continuous assurance from a versioned JSON policy. Positional "
            "targets and --input-file are disabled in policy mode."
        ),
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Compare a policy run with an approved v0.4 baseline snapshot.",
    )
    parser.add_argument(
        "--write-baseline",
        type=Path,
        help=(
            "Write the current successful policy run as a deterministic baseline. "
            "Review the diff before approving it in source control."
        ),
    )
    parser.add_argument(
        "--export-profile-definitions",
        type=Path,
        metavar="PATH",
        help=(
            "Write the canonical, static profile-definition JSON to PATH without "
            "requesting any target. This cannot be combined with audit or policy inputs."
        ),
    )
    parser.add_argument(
        "--route-comparison",
        type=Path,
        metavar="PATH",
        help=(
            "Assess the explicit same-origin routes in a versioned comparison "
            "manifest. It cannot be combined with targets, policy, or audit options."
        ),
    )
    parser.add_argument(
        "--route-baseline",
        type=Path,
        metavar="PATH",
        help=(
            "Compare a route-comparison run with an explicitly reviewed route baseline. "
            "Requires --route-comparison."
        ),
    )
    parser.add_argument(
        "--write-route-baseline",
        type=Path,
        metavar="PATH",
        help=(
            "Write a new route-baseline candidate from a complete route-comparison run. "
            "Review it before using it with --route-baseline."
        ),
    )
    parser.add_argument(
        "--create-evidence-capsule",
        type=Path,
        metavar="PATH",
        help=(
            "Create one deterministic, offline-verifiable review capsule from an "
            "existing compact review assessment. It never audits a target."
        ),
    )
    parser.add_argument(
        "--verify-evidence-capsule",
        type=Path,
        metavar="PATH",
        help=(
            "Verify one evidence capsule in place without extraction, target requests, "
            "or network access."
        ),
    )
    parser.add_argument(
        "--capsule-policy",
        type=Path,
        metavar="PATH",
        help="Policy scope to bind into --create-evidence-capsule.",
    )
    parser.add_argument(
        "--capsule-route-comparison",
        type=Path,
        metavar="PATH",
        help="Route-comparison scope to bind into --create-evidence-capsule.",
    )
    parser.add_argument(
        "--capsule-assessment",
        type=Path,
        metavar="PATH",
        help="Compact --format review-json assessment to bind into an evidence capsule.",
    )
    parser.add_argument(
        "--capsule-baseline",
        type=Path,
        metavar="PATH",
        help="Optional approved baseline to bind into --create-evidence-capsule.",
    )
    parser.add_argument(
        "--profile",
        choices=("auto", "app", "api", "brochure"),
        default="auto",
        help=(
            "Endpoint profile. Auto uses conservative response evidence; select a "
            "profile explicitly when the endpoint purpose is known."
        ),
    )
    parser.add_argument(
        "--include-query",
        action="store_true",
        help=(
            "Include URL query strings and fragments in reports. They are redacted "
            "by default because they may contain identifiers or secrets."
        ),
    )
    parser.add_argument(
        "--allow-cross-origin-redirects",
        action="store_true",
        help=(
            "Follow redirects that leave the original origin. Same-host HTTP-to-HTTPS "
            "upgrades are allowed by default; use this only for authorized destinations."
        ),
    )
    parser.add_argument(
        "--reporting-readiness",
        choices=("observe", "recommended", "required", "not_applicable"),
        default="observe",
        help="Contextual expectation for reporting endpoint and CSP linkage analysis.",
    )
    parser.add_argument(
        "--cross-origin-isolation",
        choices=("observe", "recommended", "required", "not_applicable"),
        default="observe",
        help="Contextual expectation for the COOP/COEP isolation bundle.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write report to this path instead of stdout.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="HTTP timeout in seconds.",
    )
    return parser


def build_workspace_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-headers-auditor workspace",
        description=(
            "Run the local-only Security Headers Auditor workspace on loopback."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8766,
        help="Loopback port for the local workspace. Default: 8766.",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        help="Override the per-user workspace data directory.",
    )
    parser.add_argument(
        "--allow-private-targets",
        action="store_true",
        help=(
            "Permit private, loopback, link-local, or reserved target addresses "
            "for this session. Use only for explicitly authorized internal systems."
        ),
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the workspace in the default browser.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    resolved_argv = list(sys.argv[1:] if argv is None else argv)
    if resolved_argv[:1] == ["workspace"]:
        return _run_workspace_mode(resolved_argv[1:])

    parser = build_parser()
    args = parser.parse_args(resolved_argv)

    if args.create_evidence_capsule or args.verify_evidence_capsule:
        _validate_evidence_capsule_mode(parser, args, resolved_argv)
        return _run_evidence_capsule_mode(args)

    if any(
        (
            args.capsule_policy,
            args.capsule_route_comparison,
            args.capsule_assessment,
            args.capsule_baseline,
        )
    ):
        parser.error(
            "--capsule-policy, --capsule-route-comparison, --capsule-assessment, and "
            "--capsule-baseline require --create-evidence-capsule."
        )

    if args.export_profile_definitions:
        _validate_profile_export_mode(parser, args, resolved_argv)
        _write_output(args.export_profile_definitions, render_profile_definition_export())
        return 0

    if args.route_comparison:
        _validate_route_comparison_mode(parser, args, resolved_argv)
        return _run_route_comparison_mode(args)

    if args.route_baseline or args.write_route_baseline:
        parser.error("--route-baseline and --write-route-baseline require --route-comparison.")

    if args.policy:
        if args.targets or args.input_file:
            parser.error("Do not combine --policy with positional targets or --input-file.")
        return _run_policy_mode(args)

    if args.baseline or args.write_baseline:
        parser.error("--baseline and --write-baseline require --policy.")
    if args.format in {"sarif", "junit", "review-json"}:
        parser.error(f"--format {args.format} requires --policy.")

    targets = list(args.targets)
    if args.input_file:
        targets.extend(_read_targets(args.input_file))

    targets = [target for target in (item.strip() for item in targets) if target]
    if not targets:
        parser.error("Provide at least one target or --input-file.")

    results = [
        audit_headers(
            target,
            timeout=args.timeout,
            profile=args.profile,
            include_query=args.include_query,
            allow_cross_origin_redirects=args.allow_cross_origin_redirects,
            reporting_expectation=args.reporting_readiness,
            cross_origin_isolation=args.cross_origin_isolation,
        )
        for target in targets
    ]
    renderers = {
        "markdown": render_markdown,
        "json": render_json,
        "html": render_html,
    }
    rendered = renderers[args.format](results)

    _write_output(args.output, rendered)

    return 2 if any(result.error for result in results) else 0


def _run_workspace_mode(argv: list[str]) -> int:
    parser = build_workspace_parser()
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535.")

    from .workspace.repository import WorkspaceRepository
    from .workspace.server import create_workspace_server

    database_path = (
        args.data_dir.expanduser() / "workspace.sqlite3"
        if args.data_dir
        else None
    )
    repository = WorkspaceRepository(database_path)
    server = create_workspace_server(
        repository,
        port=args.port,
        allow_private_targets=args.allow_private_targets,
    )
    scope = (
        "private targets enabled"
        if args.allow_private_targets
        else "public targets only"
    )
    print(f"Workspace: {server.guard.origin} ({scope})")
    print("Press Ctrl+C to stop. The session token is not printed.")
    try:
        server.serve_forever(open_browser=not args.no_open)
    except KeyboardInterrupt:
        print("\nWorkspace stopped.")
    return 0


def _validate_profile_export_mode(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    argv: list[str],
) -> None:
    incompatible_options = {
        "--input-file",
        "--format",
        "--policy",
        "--baseline",
        "--write-baseline",
        "--profile",
        "--include-query",
        "--allow-cross-origin-redirects",
        "--reporting-readiness",
        "--cross-origin-isolation",
        "--output",
        "--timeout",
        "--route-comparison",
        "--create-evidence-capsule",
        "--verify-evidence-capsule",
        "--capsule-policy",
        "--capsule-route-comparison",
        "--capsule-assessment",
        "--capsule-baseline",
    }
    specified_incompatible_option = any(
        item.partition("=")[0] in incompatible_options for item in argv
    )
    if args.targets or specified_incompatible_option:
        parser.error(
            "--export-profile-definitions cannot be combined with audit, policy, or report options."
        )


def _validate_route_comparison_mode(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    argv: list[str],
) -> None:
    incompatible_options = {
        "--input-file",
        "--policy",
        "--baseline",
        "--write-baseline",
        "--export-profile-definitions",
        "--profile",
        "--include-query",
        "--allow-cross-origin-redirects",
        "--reporting-readiness",
        "--cross-origin-isolation",
        "--timeout",
        "--create-evidence-capsule",
        "--verify-evidence-capsule",
        "--capsule-policy",
        "--capsule-route-comparison",
        "--capsule-assessment",
        "--capsule-baseline",
    }
    specified_incompatible_option = any(
        item.partition("=")[0] in incompatible_options for item in argv
    )
    if args.targets or specified_incompatible_option:
        parser.error(
            "--route-comparison cannot be combined with targets, policy, or audit options."
        )
    if args.format not in {"markdown", "json", "review-json"}:
        parser.error(
            "--route-comparison supports only --format markdown, json, or review-json."
        )
    if args.route_baseline and args.write_route_baseline:
        parser.error(
            "Use either --route-baseline or --write-route-baseline; review candidates before enforcement."
        )


def _run_route_comparison_mode(args: argparse.Namespace) -> int:
    try:
        config = load_route_comparison(args.route_comparison)
        baseline = load_route_baseline(args.route_baseline) if args.route_baseline else None
        run = run_route_assurance(config, baseline=baseline)
        if args.write_route_baseline:
            write_route_baseline(args.write_route_baseline, run.comparison)
    except (RouteComparisonConfigurationError, RouteBaselineCompatibilityError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    renderers = {
        "markdown": render_route_assurance_markdown,
        "json": render_route_assurance_json,
        "review-json": render_route_assurance_review_json,
    }
    rendered = renderers[args.format](run)
    _write_output(args.output, rendered)
    return run.exit_code


def _run_policy_mode(args: argparse.Namespace) -> int:
    try:
        policy = load_policy(args.policy)
        baseline = load_baseline(args.baseline) if args.baseline else None
        run = run_assurance(policy, baseline=baseline)
        if args.write_baseline:
            write_baseline(args.write_baseline, run)
    except (PolicyConfigurationError, BaselineCompatibilityError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    results = [assessment.result for assessment in run.assessments]
    renderers = {
        "markdown": lambda: render_markdown(results, assurance_run=run),
        "json": lambda: render_assurance_json(run),
        "review-json": lambda: render_assurance_review_json(run),
        "html": lambda: render_html(results, assurance_run=run),
        "sarif": lambda: render_sarif(run),
        "junit": lambda: render_junit(run),
    }
    _write_output(args.output, renderers[args.format]())
    return run.exit_code


def _validate_evidence_capsule_mode(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    argv: list[str],
) -> None:
    capsule_options = {
        "--create-evidence-capsule",
        "--verify-evidence-capsule",
        "--capsule-policy",
        "--capsule-route-comparison",
        "--capsule-assessment",
        "--capsule-baseline",
    }
    specified_options = {item.partition("=")[0] for item in argv if item.startswith("--")}
    if args.targets or specified_options - capsule_options:
        parser.error(
            "Evidence-capsule modes cannot be combined with audit, policy, route, report, or output options."
        )
    if args.create_evidence_capsule and args.verify_evidence_capsule:
        parser.error("Use either --create-evidence-capsule or --verify-evidence-capsule.")
    if args.verify_evidence_capsule:
        if any(
            (
                args.capsule_policy,
                args.capsule_route_comparison,
                args.capsule_assessment,
                args.capsule_baseline,
            )
        ):
            parser.error("--verify-evidence-capsule accepts only the capsule path.")
        return
    if (args.capsule_policy is None) == (args.capsule_route_comparison is None):
        parser.error(
            "--create-evidence-capsule requires exactly one of --capsule-policy or "
            "--capsule-route-comparison."
        )
    if args.capsule_assessment is None:
        parser.error("--create-evidence-capsule requires --capsule-assessment.")


def _run_evidence_capsule_mode(args: argparse.Namespace) -> int:
    try:
        if args.verify_evidence_capsule:
            verified = verify_evidence_capsule(args.verify_evidence_capsule)
            print(
                "Evidence capsule verified: "
                f"{verified.scope_kind} {verified.scope_name!r}; "
                f"outcome={verified.outcome}; sha256={verified.sha256}"
            )
            return 0
        verified = create_evidence_capsule(
            args.create_evidence_capsule,
            policy_path=args.capsule_policy,
            route_comparison_path=args.capsule_route_comparison,
            assessment_path=args.capsule_assessment,
            baseline_path=args.capsule_baseline,
        )
    except EvidenceCapsuleError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    print(
        "Evidence capsule created and verified: "
        f"{verified.scope_kind} {verified.scope_name!r}; "
        f"outcome={verified.outcome}; sha256={verified.sha256}"
    )
    return 0


def _write_output(path: Path | None, rendered: str) -> None:
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="" if rendered.endswith("\n") else "\n")


def _read_targets(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]


if __name__ == "__main__":
    raise SystemExit(main())
