"""Offline-verifiable, data-minimized review evidence capsules.

The capsule is intentionally a small deterministic ZIP container, not a report
archive. It binds one validated scope, a compact assessment, an optional
approved baseline, and the current static profile definitions through a SHA-256
manifest. Creation and verification never invoke the audit engine or network.
"""

from __future__ import annotations

import hashlib
import io
import json
import stat
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .assurance import (
    BASELINE_SCHEMA_VERSION,
    AssurancePolicy,
    BaselineCompatibilityError,
    KNOWN_CONTROL_KEYS,
    PolicyConfigurationError,
    parse_policy,
)
from .catalog import RULES_BY_KEY
from .ci_report import ASSURANCE_REVIEW_ARTIFACT, ASSURANCE_REVIEW_SCHEMA_VERSION
from .compliance import MAPPING_SET_VERSION
from .profile_export import build_profile_definition_export
from .route_comparison import (
    ROUTE_ASSURANCE_REVIEW_ARTIFACT,
    ROUTE_ASSURANCE_REVIEW_SCHEMA_VERSION,
    ROUTE_BASELINE_SCHEMA_VERSION,
    RouteBaselineCompatibilityError,
    RouteComparisonConfig,
    RouteComparisonConfigurationError,
    parse_route_comparison,
)


EVIDENCE_CAPSULE_SCHEMA_VERSION = "1.0"
EVIDENCE_CAPSULE_ARTIFACT = "security-headers-auditor.evidence-capsule"
MAX_SOURCE_BYTES = 512 * 1024
MAX_CAPSULE_BYTES = 2 * 1024 * 1024
MAX_ENTRY_BYTES = 512 * 1024
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_REQUIRED_ENTRY_NAMES = {
    "assessment.json",
    "capsule-manifest.json",
    "profile-definitions.json",
    "scope.json",
}
_POLICY_REVIEW_LIMITATIONS = [
    "This compact review artifact omits target URLs, raw response-header values, response metadata, and diagnostic prose.",
    "It records policy evaluation state for review; it is not a security pass, compliance decision, vulnerability finding, or browser runtime validation.",
]
_ROUTE_REVIEW_LIMITATIONS = [
    "This compact review artifact omits route URLs, raw response-header values, response metadata, and diagnostic prose.",
    "It records explicit route-manifest evaluation state for review; it is not a security pass, compliance decision, vulnerability finding, or browser runtime validation.",
]
_STATUSES = {
    "pass",
    "info",
    "observed",
    "not_applicable",
    "review",
    "warning",
    "missing",
    "error",
}
_SEVERITIES = {"info", "low", "medium", "high"}
_PROFILE_NAMES = {"app", "api", "brochure"}


class EvidenceCapsuleError(ValueError):
    """Raised when a capsule input or container violates its bounded contract."""


@dataclass(frozen=True)
class EvidenceCapsuleVerification:
    """Small, safe-to-display result returned after local verification."""

    sha256: str
    scope_kind: str
    scope_name: str
    outcome: str
    has_baseline: bool


def create_evidence_capsule(
    output_path: Path,
    *,
    policy_path: Path | None = None,
    route_comparison_path: Path | None = None,
    assessment_path: Path,
    baseline_path: Path | None = None,
) -> EvidenceCapsuleVerification:
    """Create one deterministic review capsule from already-produced evidence.

    Exactly one scope source is accepted. The assessment is validated before a
    capsule is written, so this function cannot turn a broad report, arbitrary
    JSON, or incompatible baseline into a trusted-looking archive.
    """
    if (policy_path is None) == (route_comparison_path is None):
        raise EvidenceCapsuleError(
            "Provide exactly one of a policy scope or a route-comparison scope."
        )
    _assert_new_output_path(output_path)

    if policy_path is not None:
        try:
            policy = parse_policy(_read_json_source(policy_path, "policy"))
        except PolicyConfigurationError as exc:
            raise EvidenceCapsuleError(f"Invalid capsule policy: {exc}") from exc
        scope = _policy_scope(policy)
        assessment = _read_json_source(assessment_path, "assessment")
        _validate_policy_review(assessment, policy, baseline_path is not None)
        baseline = _load_policy_baseline(baseline_path, policy) if baseline_path else None
    else:
        try:
            config = parse_route_comparison(
                _read_json_source(route_comparison_path, "route comparison manifest")
            )
        except RouteComparisonConfigurationError as exc:
            raise EvidenceCapsuleError(
                f"Invalid capsule route-comparison manifest: {exc}"
            ) from exc
        scope = _route_scope(config)
        assessment = _read_json_source(assessment_path, "assessment")
        _validate_route_review(assessment, config, baseline_path is not None)
        baseline = _load_route_baseline(baseline_path, config) if baseline_path else None

    payloads: dict[str, bytes] = {
        "assessment.json": _canonical_json(assessment),
        "profile-definitions.json": _canonical_json(build_profile_definition_export()),
        "scope.json": _canonical_json(scope),
    }
    if baseline is not None:
        payloads["baseline.json"] = _canonical_json(baseline)
    _assert_payload_sizes(payloads)
    payloads["capsule-manifest.json"] = _canonical_json(_manifest_payload(payloads))
    _assert_payload_sizes(payloads)

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(
            output_path,
            mode="x",
            compression=zipfile.ZIP_STORED,
            strict_timestamps=True,
        ) as archive:
            for name in sorted(payloads):
                info = zipfile.ZipInfo(name, date_time=_ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(info, payloads[name])
    except (OSError, zipfile.BadZipFile) as exc:
        raise EvidenceCapsuleError(f"Cannot create evidence capsule {output_path}: {exc}") from exc

    return verify_evidence_capsule(output_path)


def verify_evidence_capsule(path: Path) -> EvidenceCapsuleVerification:
    """Verify a capsule in place without extraction, target requests, or network."""
    _assert_regular_file(path, "evidence capsule", MAX_CAPSULE_BYTES)
    try:
        raw_capsule = path.read_bytes()
        if len(raw_capsule) > MAX_CAPSULE_BYTES:
            raise EvidenceCapsuleError(
                f"Evidence capsule exceeds the {MAX_CAPSULE_BYTES}-byte limit."
            )
        with zipfile.ZipFile(io.BytesIO(raw_capsule), mode="r") as archive:
            payloads = _read_capsule_entries(archive)
    except (OSError, zipfile.BadZipFile) as exc:
        raise EvidenceCapsuleError(f"Cannot read evidence capsule {path}: {exc}") from exc

    manifest = _parse_canonical_object(payloads["capsule-manifest.json"], "capsule manifest")
    _validate_manifest(manifest, payloads)
    scope = _parse_canonical_object(payloads["scope.json"], "scope")
    assessment = _parse_canonical_object(payloads["assessment.json"], "assessment")
    profile_definitions = _parse_canonical_object(
        payloads["profile-definitions.json"], "profile definitions"
    )
    if profile_definitions != build_profile_definition_export():
        raise EvidenceCapsuleError(
            "Capsule profile definitions do not match this tool's canonical static definitions."
        )

    baseline = (
        _parse_canonical_object(payloads["baseline.json"], "baseline")
        if "baseline.json" in payloads
        else None
    )
    scope_kind, scope_name = _validate_bound_evidence(scope, assessment, baseline)
    return EvidenceCapsuleVerification(
        sha256=hashlib.sha256(raw_capsule).hexdigest(),
        scope_kind=scope_kind,
        scope_name=scope_name,
        outcome=str(assessment["outcome"]),
        has_baseline=baseline is not None,
    )


def _policy_scope(policy: AssurancePolicy) -> dict[str, Any]:
    scope = {
        "kind": "policy",
        "policy": {
            "schema_version": policy.schema_version,
            "methodology_version": policy.methodology_version,
            "name": policy.name,
            "defaults": {
                "allow_auto_profile": any(target.profile == "auto" for target in policy.targets)
            },
            "targets": [
                _json_value(asdict(target))
                for target in sorted(policy.targets, key=lambda item: item.id)
            ],
        },
    }
    _parse_policy_scope(scope)
    return scope


def _route_scope(config: RouteComparisonConfig) -> dict[str, Any]:
    scope = {
        "kind": "route-comparison",
        "manifest": {
            "schema_version": config.schema_version,
            "name": config.name,
            "origin": config.origin,
            "routes": [
                {"id": route.id, "path": route.path, "profile": route.profile.value}
                for route in sorted(config.routes, key=lambda item: item.id)
            ],
        },
    }
    _parse_route_scope(scope)
    return scope


def _load_policy_baseline(path: Path, policy: AssurancePolicy) -> dict[str, Any]:
    _assert_regular_file(path, "policy baseline", MAX_SOURCE_BYTES)
    try:
        from .assurance import load_baseline

        baseline = load_baseline(path)
    except BaselineCompatibilityError as exc:
        raise EvidenceCapsuleError(f"Invalid capsule policy baseline: {exc}") from exc
    if baseline["policy_name"] != policy.name:
        raise EvidenceCapsuleError("Capsule policy baseline does not match the policy name.")
    if set(baseline["targets"]) != {target.id for target in policy.targets}:
        raise EvidenceCapsuleError("Capsule policy baseline does not match the policy target ids.")
    for target_id, target in baseline["targets"].items():
        _safe_url(target["target"], f"baseline target {target_id!r}")
    return baseline


def _load_route_baseline(
    path: Path,
    config: RouteComparisonConfig,
) -> dict[str, Any]:
    _assert_regular_file(path, "route baseline", MAX_SOURCE_BYTES)
    try:
        from .route_comparison import load_route_baseline

        baseline = load_route_baseline(path)
    except RouteBaselineCompatibilityError as exc:
        raise EvidenceCapsuleError(f"Invalid capsule route baseline: {exc}") from exc
    if baseline["manifest"] != _route_scope(config)["manifest"]:
        raise EvidenceCapsuleError("Capsule route baseline does not match the route manifest.")
    return baseline


def _validate_bound_evidence(
    scope: dict[str, Any],
    assessment: dict[str, Any],
    baseline: dict[str, Any] | None,
) -> tuple[str, str]:
    kind = scope.get("kind")
    if kind == "policy":
        policy = _parse_policy_scope(scope)
        _validate_policy_review(assessment, policy, baseline is not None)
        if baseline is not None:
            _validate_policy_baseline_payload(baseline, policy)
        return kind, policy.name
    if kind == "route-comparison":
        config = _parse_route_scope(scope)
        _validate_route_review(assessment, config, baseline is not None)
        if baseline is not None:
            _validate_route_baseline_payload(baseline, config)
        return kind, config.name
    raise EvidenceCapsuleError("Capsule scope kind must be policy or route-comparison.")


def _parse_policy_scope(scope: dict[str, Any]) -> AssurancePolicy:
    _require_exact_keys(scope, {"kind", "policy"}, "policy scope")
    if scope.get("kind") != "policy" or not isinstance(scope.get("policy"), dict):
        raise EvidenceCapsuleError("Policy scope must contain a policy object.")
    policy_payload = scope["policy"]
    _require_exact_keys(
        policy_payload,
        {"schema_version", "methodology_version", "name", "defaults", "targets"},
        "capsule policy",
    )
    try:
        policy = parse_policy(policy_payload)
    except PolicyConfigurationError as exc:
        raise EvidenceCapsuleError(f"Capsule policy scope is invalid: {exc}") from exc
    if _json_value(_policy_scope_unchecked(policy)) != _json_value(scope):
        raise EvidenceCapsuleError("Capsule policy scope is not canonical.")
    for target in policy.targets:
        _safe_url(target.url, f"policy target {target.id!r}")
        if target.include_query:
            raise EvidenceCapsuleError(
                f"Policy target {target.id!r} enables include_query, which capsules forbid."
            )
        if target.allow_cross_origin_redirects:
            raise EvidenceCapsuleError(
                f"Policy target {target.id!r} enables cross-origin redirects, which capsules forbid."
            )
    return policy


def _policy_scope_unchecked(policy: AssurancePolicy) -> dict[str, Any]:
    return {
        "kind": "policy",
        "policy": {
            "schema_version": policy.schema_version,
            "methodology_version": policy.methodology_version,
            "name": policy.name,
            "defaults": {
                "allow_auto_profile": any(target.profile == "auto" for target in policy.targets)
            },
            "targets": [
                _json_value(asdict(target))
                for target in sorted(policy.targets, key=lambda item: item.id)
            ],
        },
    }


def _parse_route_scope(scope: dict[str, Any]) -> RouteComparisonConfig:
    _require_exact_keys(scope, {"kind", "manifest"}, "route scope")
    if scope.get("kind") != "route-comparison" or not isinstance(scope.get("manifest"), dict):
        raise EvidenceCapsuleError("Route scope must contain a route-comparison manifest.")
    try:
        config = parse_route_comparison(scope["manifest"])
    except RouteComparisonConfigurationError as exc:
        raise EvidenceCapsuleError(f"Capsule route scope is invalid: {exc}") from exc
    if _json_value(_route_scope_unchecked(config)) != _json_value(scope):
        raise EvidenceCapsuleError("Capsule route scope is not canonical.")
    return config


def _route_scope_unchecked(config: RouteComparisonConfig) -> dict[str, Any]:
    return {
        "kind": "route-comparison",
        "manifest": {
            "schema_version": config.schema_version,
            "name": config.name,
            "origin": config.origin,
            "routes": [
                {"id": route.id, "path": route.path, "profile": route.profile.value}
                for route in sorted(config.routes, key=lambda item: item.id)
            ],
        },
    }


def _validate_policy_baseline_payload(
    baseline: dict[str, Any], policy: AssurancePolicy
) -> None:
    try:
        from .assurance import validate_baseline

        validate_baseline(baseline)
    except BaselineCompatibilityError as exc:
        raise EvidenceCapsuleError(f"Capsule policy baseline is invalid: {exc}") from exc
    if baseline["policy_name"] != policy.name:
        raise EvidenceCapsuleError("Capsule policy baseline does not match the policy name.")
    if set(baseline["targets"]) != {target.id for target in policy.targets}:
        raise EvidenceCapsuleError("Capsule policy baseline does not match the policy target ids.")
    for target_id, target in baseline["targets"].items():
        _safe_url(target["target"], f"baseline target {target_id!r}")


def _validate_route_baseline_payload(
    baseline: dict[str, Any], config: RouteComparisonConfig
) -> None:
    try:
        from .route_comparison import validate_route_baseline

        validate_route_baseline(baseline)
    except RouteBaselineCompatibilityError as exc:
        raise EvidenceCapsuleError(f"Capsule route baseline is invalid: {exc}") from exc
    if baseline["manifest"] != _route_scope_unchecked(config)["manifest"]:
        raise EvidenceCapsuleError("Capsule route baseline does not match the route manifest.")


def _validate_policy_review(
    payload: dict[str, Any], policy: AssurancePolicy, has_baseline: bool
) -> None:
    _require_exact_keys(
        payload,
        {
            "schema_version",
            "artifact",
            "methodology_version",
            "mapping_set_version",
            "policy_name",
            "policy_schema_version",
            "baseline_schema_version",
            "outcome",
            "exit_code",
            "assessments",
            "policy_violations",
            "regressions",
            "operational_error_count",
            "limitations",
        },
        "policy review assessment",
    )
    _require_value(payload, "schema_version", ASSURANCE_REVIEW_SCHEMA_VERSION, "policy review")
    _require_value(payload, "artifact", ASSURANCE_REVIEW_ARTIFACT, "policy review")
    _require_value(payload, "methodology_version", policy.methodology_version, "policy review")
    _require_value(payload, "mapping_set_version", MAPPING_SET_VERSION, "policy review")
    _require_value(payload, "policy_name", policy.name, "policy review")
    _require_value(payload, "policy_schema_version", policy.schema_version, "policy review")
    _validate_baseline_binding(
        payload.get("baseline_schema_version"), BASELINE_SCHEMA_VERSION, has_baseline, "policy review"
    )
    _validate_review_assessments(
        payload.get("assessments"),
        {target.id: target.profile for target in policy.targets},
        "target_id",
        allow_auto_profile=True,
    )
    _validate_diagnostics(payload.get("policy_violations"), "target_id", {target.id for target in policy.targets}, "policy violation")
    _validate_diagnostics(payload.get("regressions"), "target_id", {target.id for target in policy.targets}, "regression")
    _validate_outcome(payload, _POLICY_REVIEW_LIMITATIONS, "policy review")


def _validate_route_review(
    payload: dict[str, Any], config: RouteComparisonConfig, has_baseline: bool
) -> None:
    _require_exact_keys(
        payload,
        {
            "schema_version",
            "artifact",
            "methodology_version",
            "mapping_set_version",
            "manifest_name",
            "manifest_schema_version",
            "baseline_schema_version",
            "outcome",
            "exit_code",
            "routes",
            "regressions",
            "operational_error_count",
            "control_variance_count",
            "limitations",
        },
        "route review assessment",
    )
    _require_value(payload, "schema_version", ROUTE_ASSURANCE_REVIEW_SCHEMA_VERSION, "route review")
    _require_value(payload, "artifact", ROUTE_ASSURANCE_REVIEW_ARTIFACT, "route review")
    _require_value(payload, "methodology_version", "0.5.0", "route review")
    _require_value(payload, "mapping_set_version", MAPPING_SET_VERSION, "route review")
    _require_value(payload, "manifest_name", config.name, "route review")
    _require_value(payload, "manifest_schema_version", config.schema_version, "route review")
    _validate_baseline_binding(
        payload.get("baseline_schema_version"), ROUTE_BASELINE_SCHEMA_VERSION, has_baseline, "route review"
    )
    _validate_review_assessments(
        payload.get("routes"),
        {route.id: route.profile.value for route in config.routes},
        "route_id",
        allow_auto_profile=False,
    )
    _validate_diagnostics(payload.get("regressions"), "route_id", {route.id for route in config.routes}, "route regression")
    count = payload.get("control_variance_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise EvidenceCapsuleError("Route review control_variance_count must be a non-negative integer.")
    _validate_outcome(payload, _ROUTE_REVIEW_LIMITATIONS, "route review")


def _validate_baseline_binding(
    value: Any, expected: str, has_baseline: bool, label: str
) -> None:
    if has_baseline and value != expected:
        raise EvidenceCapsuleError(f"{label} does not bind the supplied baseline schema.")
    if not has_baseline and value is not None:
        raise EvidenceCapsuleError(f"{label} claims a baseline that is absent from the capsule.")


def _validate_review_assessments(
    entries: Any,
    expected_profiles: dict[str, str],
    identifier: str,
    *,
    allow_auto_profile: bool,
) -> None:
    if not isinstance(entries, list):
        raise EvidenceCapsuleError("Review assessments must be an array.")
    ids: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise EvidenceCapsuleError("Each review assessment must be an object.")
        _require_exact_keys(
            entry,
            {identifier, "selected_profile", "score", "scored_controls"},
            "review assessment",
        )
        item_id = entry.get(identifier)
        if not isinstance(item_id, str) or item_id not in expected_profiles:
            raise EvidenceCapsuleError("Review assessment has an unknown identifier.")
        ids.append(item_id)
        selected_profile = entry.get("selected_profile")
        if selected_profile not in _PROFILE_NAMES:
            raise EvidenceCapsuleError("Review assessment has an invalid selected profile.")
        if not allow_auto_profile or expected_profiles[item_id] != "auto":
            if selected_profile != expected_profiles[item_id]:
                raise EvidenceCapsuleError("Review assessment profile does not match its scope.")
        score = entry.get("score")
        controls = entry.get("scored_controls")
        if score is None:
            if controls != []:
                raise EvidenceCapsuleError("An operationally incomplete assessment cannot contain controls.")
        elif isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
            raise EvidenceCapsuleError("Review assessment score must be an integer from 0 through 100.")
        _validate_scored_controls(controls)
    if ids != sorted(expected_profiles) or len(set(ids)) != len(ids):
        raise EvidenceCapsuleError("Review assessment ids must exactly match the sorted scope ids.")


def _validate_scored_controls(controls: Any) -> None:
    if not isinstance(controls, list):
        raise EvidenceCapsuleError("Review scored_controls must be an array.")
    keys: list[str] = []
    for control in controls:
        if not isinstance(control, dict):
            raise EvidenceCapsuleError("A review control must be an object.")
        _require_exact_keys(
            control, {"key", "status", "severity", "points", "max_points"}, "review control"
        )
        key = control.get("key")
        if not isinstance(key, str) or key not in RULES_BY_KEY:
            raise EvidenceCapsuleError("Review control has an unknown key.")
        keys.append(key)
        if control.get("status") not in _STATUSES or control.get("severity") not in _SEVERITIES:
            raise EvidenceCapsuleError("Review control has an invalid status or severity.")
        for field in ("points", "max_points"):
            value = control.get(field)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise EvidenceCapsuleError(f"Review control has an invalid {field} value.")
        if control["points"] > control["max_points"]:
            raise EvidenceCapsuleError("Review control points cannot exceed max_points.")
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise EvidenceCapsuleError("Review controls must be unique and sorted by key.")


def _validate_diagnostics(
    items: Any, identifier: str, valid_ids: set[str], label: str
) -> None:
    if not isinstance(items, list):
        raise EvidenceCapsuleError(f"{label.capitalize()}s must be an array.")
    for item in items:
        if not isinstance(item, dict):
            raise EvidenceCapsuleError(f"Each {label} must be an object.")
        _require_exact_keys(
            item, {identifier, "code", "severity", "control_key"}, label
        )
        if not isinstance(item.get(identifier), str) or item[identifier] not in valid_ids:
            raise EvidenceCapsuleError(f"{label.capitalize()} has an unknown scope id.")
        if not isinstance(item.get("code"), str) or not item["code"] or len(item["code"]) > 160:
            raise EvidenceCapsuleError(f"{label.capitalize()} has an invalid code.")
        if item.get("severity") not in _SEVERITIES:
            raise EvidenceCapsuleError(f"{label.capitalize()} has an invalid severity.")
        key = item.get("control_key")
        if key is not None and (not isinstance(key, str) or key not in KNOWN_CONTROL_KEYS):
            raise EvidenceCapsuleError(f"{label.capitalize()} has an invalid control key.")


def _validate_outcome(payload: dict[str, Any], limitations: list[str], label: str) -> None:
    errors = payload.get("operational_error_count")
    if isinstance(errors, bool) or not isinstance(errors, int) or errors < 0:
        raise EvidenceCapsuleError(f"{label.capitalize()} operational_error_count must be a non-negative integer.")
    failures = len(payload.get("regressions", [])) + len(payload.get("policy_violations", []))
    expected_outcome, expected_exit_code = (
        ("operational_error", 2)
        if errors
        else (("failed", 1) if failures else ("passed", 0))
    )
    if payload.get("outcome") != expected_outcome or payload.get("exit_code") != expected_exit_code:
        raise EvidenceCapsuleError(f"{label.capitalize()} outcome and exit code are inconsistent.")
    if payload.get("limitations") != limitations:
        raise EvidenceCapsuleError(f"{label.capitalize()} limitations do not match the compact contract.")


def _manifest_payload(payloads: dict[str, bytes]) -> dict[str, Any]:
    return {
        "schema_version": EVIDENCE_CAPSULE_SCHEMA_VERSION,
        "artifact": EVIDENCE_CAPSULE_ARTIFACT,
        "entries": [
            {
                "path": name,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            for name, payload in sorted(payloads.items())
            if name != "capsule-manifest.json"
        ],
        "limitations": [
            "The manifest detects content changes only when compared with a trusted expected digest; it does not authenticate an author.",
            "The capsule is review evidence, not a security attestation, compliance decision, vulnerability finding, or proof of browser runtime behavior.",
        ],
    }


def _validate_manifest(manifest: dict[str, Any], payloads: dict[str, bytes]) -> None:
    _require_exact_keys(manifest, {"schema_version", "artifact", "entries", "limitations"}, "capsule manifest")
    _require_value(manifest, "schema_version", EVIDENCE_CAPSULE_SCHEMA_VERSION, "capsule manifest")
    _require_value(manifest, "artifact", EVIDENCE_CAPSULE_ARTIFACT, "capsule manifest")
    expected_names = sorted(name for name in payloads if name != "capsule-manifest.json")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != len(expected_names):
        raise EvidenceCapsuleError("Capsule manifest entries are incomplete.")
    names: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise EvidenceCapsuleError("Capsule manifest entry must be an object.")
        _require_exact_keys(entry, {"path", "bytes", "sha256"}, "capsule manifest entry")
        name = entry.get("path")
        if not isinstance(name, str) or name not in payloads or name == "capsule-manifest.json":
            raise EvidenceCapsuleError("Capsule manifest has an invalid entry path.")
        names.append(name)
        if entry.get("bytes") != len(payloads[name]):
            raise EvidenceCapsuleError(f"Capsule manifest byte count does not match {name}.")
        if entry.get("sha256") != hashlib.sha256(payloads[name]).hexdigest():
            raise EvidenceCapsuleError(f"Capsule manifest digest does not match {name}.")
    if names != expected_names:
        raise EvidenceCapsuleError("Capsule manifest entries must be complete and sorted.")
    expected_limitations = [
        "The manifest detects content changes only when compared with a trusted expected digest; it does not authenticate an author.",
        "The capsule is review evidence, not a security attestation, compliance decision, vulnerability finding, or proof of browser runtime behavior.",
    ]
    if manifest.get("limitations") != expected_limitations:
        raise EvidenceCapsuleError("Capsule manifest limitations are invalid.")


def _read_capsule_entries(archive: zipfile.ZipFile) -> dict[str, bytes]:
    infos = archive.infolist()
    names = [info.filename for info in infos]
    expected = set(_REQUIRED_ENTRY_NAMES)
    if "baseline.json" in names:
        expected.add("baseline.json")
    if len(infos) != len(expected) or set(names) != expected or len(set(names)) != len(names):
        raise EvidenceCapsuleError("Capsule contains unexpected, missing, or duplicate entries.")
    if names != sorted(names):
        raise EvidenceCapsuleError("Capsule entries must use deterministic sorted order.")

    payloads: dict[str, bytes] = {}
    for info in infos:
        if info.is_dir() or info.flag_bits & 0x1:
            raise EvidenceCapsuleError("Capsule entries must be regular, unencrypted files.")
        if info.compress_type != zipfile.ZIP_STORED or info.compress_size != info.file_size:
            raise EvidenceCapsuleError("Capsule entries must use uncompressed bounded storage.")
        if info.file_size > MAX_ENTRY_BYTES or info.date_time != _ZIP_TIMESTAMP:
            raise EvidenceCapsuleError("Capsule entry exceeds bounds or has non-deterministic metadata.")
        mode = info.external_attr >> 16
        if stat.S_IFMT(mode) != stat.S_IFREG or mode & 0o077:
            raise EvidenceCapsuleError("Capsule entry permissions or type are unsafe.")
        data = archive.read(info)
        if len(data) != info.file_size:
            raise EvidenceCapsuleError("Capsule entry size changed while reading.")
        payloads[info.filename] = data
    return payloads


def _read_json_source(path: Path | None, label: str) -> dict[str, Any]:
    if path is None:
        raise EvidenceCapsuleError(f"A {label} path is required.")
    _assert_regular_file(path, label, MAX_SOURCE_BYTES)
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_SOURCE_BYTES:
            raise EvidenceCapsuleError(f"{label.capitalize()} exceeds the {MAX_SOURCE_BYTES}-byte limit.")
        return _parse_json_object(raw, label)
    except OSError as exc:
        raise EvidenceCapsuleError(f"Cannot read {label} {path}: {exc}") from exc


def _parse_canonical_object(data: bytes, label: str) -> dict[str, Any]:
    payload = _parse_json_object(data, label)
    if _canonical_json(payload) != data:
        raise EvidenceCapsuleError(f"Capsule {label} is not canonically serialized.")
    return payload


def _parse_json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        decoded = data.decode("utf-8")
        payload = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise EvidenceCapsuleError(f"{label.capitalize()} is not valid strict UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise EvidenceCapsuleError(f"{label.capitalize()} root must be a JSON object.")
    return payload


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_non_finite_number(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r}")


def _canonical_json(payload: Any) -> bytes:
    try:
        return (
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as exc:
        raise EvidenceCapsuleError(f"Capsule content cannot be canonically serialized: {exc}") from exc


def _json_value(value: Any) -> Any:
    return json.loads(_canonical_json(value))


def _assert_payload_sizes(payloads: dict[str, bytes]) -> None:
    if any(len(payload) > MAX_ENTRY_BYTES for payload in payloads.values()):
        raise EvidenceCapsuleError("Capsule content exceeds the per-entry size limit.")
    if sum(len(payload) for payload in payloads.values()) > MAX_CAPSULE_BYTES:
        raise EvidenceCapsuleError("Capsule content exceeds the total size limit.")


def _assert_new_output_path(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise EvidenceCapsuleError(
            f"Evidence capsule {path} already exists; choose a new path rather than overwriting it."
        )


def _assert_regular_file(path: Path, label: str, maximum: int) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceCapsuleError(f"Cannot access {label} {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise EvidenceCapsuleError(f"{label.capitalize()} must be a regular non-symlink file.")
    if metadata.st_size > maximum:
        raise EvidenceCapsuleError(f"{label.capitalize()} exceeds the {maximum}-byte limit.")


def _safe_url(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise EvidenceCapsuleError(f"{label.capitalize()} must be a bounded non-empty URL.")
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as exc:
        raise EvidenceCapsuleError(f"{label.capitalize()} has an invalid URL port: {exc}") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise EvidenceCapsuleError(
            f"{label.capitalize()} must be HTTP(S) without credentials, query strings, or fragments."
        )


def _require_exact_keys(payload: dict[str, Any], expected: set[str], label: str) -> None:
    if set(payload) != expected:
        unexpected = sorted(set(payload) - expected)
        missing = sorted(expected - set(payload))
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise EvidenceCapsuleError(f"{label.capitalize()} fields are invalid ({'; '.join(details)}).")


def _require_value(payload: dict[str, Any], key: str, expected: Any, label: str) -> None:
    if payload.get(key) != expected:
        raise EvidenceCapsuleError(f"{label.capitalize()} {key} is incompatible.")
