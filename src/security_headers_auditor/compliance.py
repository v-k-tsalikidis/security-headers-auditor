"""Versioned, evidence-only mappings to security control catalogues."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any


@dataclass(frozen=True)
class EvidenceMapping:
    control_key: str
    framework_id: str
    framework: str
    framework_version: str
    requirement: str
    evidence_family: str
    relationship: str
    confidence: str
    rationale: str
    limitations: str
    citation_key: str

    @property
    def label(self) -> str:
        return (
            f"{self.framework} {self.framework_version} "
            f"{self.requirement} ({self.evidence_family}; {self.relationship})"
        )


@dataclass(frozen=True)
class MappingManifest:
    schema_version: str
    mapping_set_id: str
    mapping_set_version: str
    last_reviewed: str
    claims_policy: str
    mappings: tuple[EvidenceMapping, ...]


def _load_manifest() -> MappingManifest:
    resource = files("security_headers_auditor").joinpath(
        "data/compliance_evidence_v1.json"
    )
    payload = json.loads(resource.read_text(encoding="utf-8"))
    _validate_manifest_payload(payload)

    frameworks = payload["frameworks"]
    mappings = tuple(
        EvidenceMapping(
            control_key=item["control_key"],
            framework_id=item["framework"],
            framework=frameworks[item["framework"]]["name"],
            framework_version=frameworks[item["framework"]]["version"],
            requirement=item["requirement"],
            evidence_family=item["evidence_family"],
            relationship=item["relationship"],
            confidence=item["confidence"],
            rationale=item["rationale"],
            limitations=item["limitations"],
            citation_key=item.get(
                "citation_key",
                frameworks[item["framework"]]["citation_key"],
            ),
        )
        for item in payload["mappings"]
    )
    return MappingManifest(
        schema_version=payload["schema_version"],
        mapping_set_id=payload["mapping_set_id"],
        mapping_set_version=payload["mapping_set_version"],
        last_reviewed=payload["last_reviewed"],
        claims_policy=payload["claims_policy"],
        mappings=mappings,
    )


def _validate_manifest_payload(payload: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "mapping_set_id",
        "mapping_set_version",
        "last_reviewed",
        "claims_policy",
        "frameworks",
        "mappings",
    }
    missing = required - payload.keys()
    if missing:
        raise ValueError(
            "Compliance evidence manifest is missing: " + ", ".join(sorted(missing))
        )
    if payload["claims_policy"] != "supporting-evidence-only":
        raise ValueError("Compliance evidence claims policy must remain evidence-only.")

    frameworks = payload["frameworks"]
    evidence_families = {
        "verification-requirement",
        "test-procedure",
        "security-control",
        "threat-mitigation",
        "defensive-technique",
        "technical-format",
    }
    confidence_levels = {"direct", "strong", "related", "inferred"}
    seen: set[tuple[str, str, str]] = set()
    for item in payload["mappings"]:
        framework_id = item.get("framework")
        if framework_id not in frameworks:
            raise ValueError(f"Unknown mapping framework: {framework_id}")
        key = (
            str(item.get("control_key")),
            str(framework_id),
            str(item.get("requirement")),
        )
        if key in seen:
            raise ValueError(f"Duplicate compliance evidence mapping: {key}")
        seen.add(key)
        for field in (
            "control_key",
            "requirement",
            "evidence_family",
            "relationship",
            "confidence",
            "rationale",
            "limitations",
        ):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError(f"Invalid mapping field {field}: {key}")
        if item["evidence_family"] not in evidence_families:
            raise ValueError(
                f"Unknown evidence family {item['evidence_family']}: {key}"
            )
        if item["confidence"] not in confidence_levels:
            raise ValueError(f"Unknown mapping confidence {item['confidence']}: {key}")


MAPPING_MANIFEST = _load_manifest()
MAPPING_SET_VERSION = MAPPING_MANIFEST.mapping_set_version


def mappings_for_control(control_key: str) -> tuple[EvidenceMapping, ...]:
    return tuple(
        mapping
        for mapping in MAPPING_MANIFEST.mappings
        if mapping.control_key == control_key
    )
