"""Deterministic workspace document migrations."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable


CURRENT_WORKSPACE_SCHEMA_VERSION = "1.2"


class WorkspaceMigrationError(ValueError):
    """Raised when a workspace document cannot be migrated safely."""


@dataclass(frozen=True)
class MigrationResult:
    document: dict[str, Any]
    applied: tuple[str, ...]


MigrationFunction = Callable[[dict[str, Any]], dict[str, Any]]


def _migrate_1_0_to_1_1(payload: dict[str, Any]) -> dict[str, Any]:
    """Add workspace-only disabled-target state without changing policy semantics."""
    migrated = deepcopy(payload)
    migrated["schema_version"] = "1.1"
    migrated["disabled_target_ids"] = []
    return migrated


def _migrate_1_1_to_1_2(payload: dict[str, Any]) -> dict[str, Any]:
    """Add bounded, data-minimized audit-session history."""
    migrated = deepcopy(payload)
    migrated["schema_version"] = "1.2"
    migrated["audit_history"] = []
    return migrated


# Migrations are registered by exact source version. Keeping this explicit
# prevents best-effort field copying or silent interpretation of unknown schemas.
MIGRATIONS: dict[str, tuple[str, str, MigrationFunction]] = {
    "1.0": ("workspace-1.0-to-1.1", "1.1", _migrate_1_0_to_1_1),
    "1.1": ("workspace-1.1-to-1.2", "1.2", _migrate_1_1_to_1_2),
}


def migrate_workspace(payload: dict[str, Any]) -> MigrationResult:
    """Return a migrated deep copy without mutating the imported object."""
    if not isinstance(payload, dict):
        raise WorkspaceMigrationError("Workspace root must be a JSON object.")
    version = payload.get("schema_version")
    if not isinstance(version, str) or not version:
        raise WorkspaceMigrationError(
            "Workspace requires a non-empty schema_version."
        )

    document = deepcopy(payload)
    applied: list[str] = []
    visited: set[str] = set()

    while version != CURRENT_WORKSPACE_SCHEMA_VERSION:
        if version in visited:
            raise WorkspaceMigrationError(
                f"Workspace migration cycle detected at schema {version!r}."
            )
        visited.add(version)
        step = MIGRATIONS.get(version)
        if step is None:
            raise WorkspaceMigrationError(
                f"Unsupported workspace schema {version!r}; expected "
                f"{CURRENT_WORKSPACE_SCHEMA_VERSION!r} or a supported migration path."
            )
        migration_id, target_version, migrate = step
        document = migrate(deepcopy(document))
        if not isinstance(document, dict):
            raise WorkspaceMigrationError(
                f"Migration {migration_id!r} did not return a JSON object."
            )
        if document.get("schema_version") != target_version:
            raise WorkspaceMigrationError(
                f"Migration {migration_id!r} did not produce schema "
                f"{target_version!r}."
            )
        applied.append(migration_id)
        version = target_version

    return MigrationResult(document=document, applied=tuple(applied))
