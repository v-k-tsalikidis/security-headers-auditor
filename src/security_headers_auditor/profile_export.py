"""Deterministic, local-only export of response-profile definitions."""

from __future__ import annotations

import json
from typing import Any

from . import METHODOLOGY_VERSION, __version__
from .catalog import CITATIONS, RULES
from .compliance import MAPPING_MANIFEST, MAPPING_SET_VERSION, mappings_for_control
from .profiles import PROFILE_DEFINITIONS, ProfileName


PROFILE_DEFINITION_EXPORT_SCHEMA_VERSION = "1.0"
PROFILE_DEFINITION_EXPORT_ARTIFACT = "security-headers-auditor.profile-definitions"

_LIMITATIONS = (
    "This is a static profile-definition export. It contains no target, request, response, "
    "or runtime assessment evidence.",
    "A profile defines this tool's expected controls for a response context; it does not "
    "establish that a live endpoint has that context or that its configuration is secure.",
    "Supporting evidence mappings are engineering context only. They are not compliance "
    "certification, framework endorsement, or proof of implementation effectiveness.",
    "Automatic profile selection is intentionally excluded because it depends on one live "
    "response. Select a profile explicitly when the endpoint purpose is known.",
)


def build_profile_definition_export() -> dict[str, Any]:
    """Return the canonical, network-free profile-definition manifest.

    The manifest intentionally has no generation timestamp so that source-control and CI
    consumers can compare it byte-for-byte after canonical JSON serialization.
    """
    referenced_citations: set[str] = set()
    profiles: list[dict[str, Any]] = []

    for profile_name in ProfileName:
        definition = PROFILE_DEFINITIONS[profile_name]
        profile_controls: list[dict[str, Any]] = []
        for rule in RULES:
            policy = definition.policies[rule.key]
            mappings = mappings_for_control(rule.key)
            citation_keys = tuple(
                dict.fromkeys(
                    (*rule.citation_keys, *(mapping.citation_key for mapping in mappings))
                )
            )
            referenced_citations.update(citation_keys)
            profile_controls.append(
                {
                    "key": rule.key,
                    "header_name": rule.name,
                    "purpose": rule.purpose,
                    "recommendation": rule.recommendation,
                    "applicability": policy.applicability.value,
                    "score_weight": policy.weight,
                    "profile_rationale": policy.rationale,
                    "citation_keys": list(citation_keys),
                    "standards": list(rule.standards),
                    "supporting_evidence_mappings": [
                        {
                            "framework_id": mapping.framework_id,
                            "framework": mapping.framework,
                            "framework_version": mapping.framework_version,
                            "requirement": mapping.requirement,
                            "evidence_family": mapping.evidence_family,
                            "relationship": mapping.relationship,
                            "confidence": mapping.confidence,
                            "rationale": mapping.rationale,
                            "limitations": mapping.limitations,
                            "citation_key": mapping.citation_key,
                        }
                        for mapping in mappings
                    ],
                }
            )
        profiles.append(
            {
                "id": definition.name.value,
                "label": definition.label,
                "description": definition.description,
                "scored_weight_total": sum(
                    policy.weight for policy in definition.policies.values()
                ),
                "controls": profile_controls,
            }
        )

    return {
        "schema_version": PROFILE_DEFINITION_EXPORT_SCHEMA_VERSION,
        "artifact": PROFILE_DEFINITION_EXPORT_ARTIFACT,
        "tool_version": __version__,
        "methodology_version": METHODOLOGY_VERSION,
        "evidence_mapping_set_version": MAPPING_SET_VERSION,
        "evidence_claims_policy": MAPPING_MANIFEST.claims_policy,
        "limitations": list(_LIMITATIONS),
        "profiles": profiles,
        "citations": [
            {
                "key": citation.key,
                "title": citation.title,
                "publisher": citation.publisher,
                "source_type": citation.source_type,
                "url": citation.url,
                "accessed": citation.accessed,
            }
            for key, citation in sorted(CITATIONS.items())
            if key in referenced_citations
        ],
    }


def render_profile_definition_export() -> str:
    """Render the canonical manifest as stable, newline-terminated JSON."""
    return json.dumps(
        build_profile_definition_export(),
        indent=2,
        sort_keys=True,
    ) + "\n"
