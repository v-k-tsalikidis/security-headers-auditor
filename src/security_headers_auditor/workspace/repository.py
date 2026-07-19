"""SQLite persistence for local workspace documents."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .migrations import migrate_workspace
from .schema import validate_workspace


DB_VERSION = 1
DATABASE_FILENAME = "workspace.sqlite3"


class WorkspaceRepositoryError(RuntimeError):
    """Base repository failure."""


class WorkspaceConflictError(WorkspaceRepositoryError):
    """Raised when a stale revision attempts to overwrite newer state."""


class WorkspaceNotFoundError(WorkspaceRepositoryError):
    """Raised when a requested workspace does not exist."""


class WorkspaceDatabaseVersionError(WorkspaceRepositoryError):
    """Raised when the database layout is newer than this application."""


@dataclass(frozen=True)
class WorkspaceRecord:
    document: dict[str, Any]
    revision: int


class WorkspaceRepository:
    """Persist canonical workspaces as atomic versioned JSON documents."""

    def __init__(self, database_path: Path | None = None):
        self.database_path = database_path or default_database_path()
        self._prepare_directory()
        self._initialize()

    def list_workspaces(self) -> tuple[dict[str, Any], ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT workspace_id, revision, schema_version, name, updated_at
                FROM workspaces
                ORDER BY updated_at DESC, name COLLATE NOCASE
                """
            ).fetchall()
        return tuple(
            {
                "workspace_id": row["workspace_id"],
                "revision": row["revision"],
                "schema_version": row["schema_version"],
                "name": row["name"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        )

    def get(self, workspace_id: str) -> WorkspaceRecord:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT revision, document_json
                FROM workspaces
                WHERE workspace_id = ?
                """,
                (workspace_id,),
            ).fetchone()
        if row is None:
            raise WorkspaceNotFoundError(
                f"Workspace {workspace_id!r} was not found."
            )
        payload = json.loads(row["document_json"])
        migrated = migrate_workspace(payload)
        validate_workspace(migrated.document)
        return WorkspaceRecord(document=migrated.document, revision=row["revision"])

    def create(self, document: dict[str, Any]) -> WorkspaceRecord:
        migrated = migrate_workspace(document)
        validate_workspace(migrated.document)
        canonical = _canonical_json(migrated.document)
        workspace_id = migrated.document["workspace_id"]
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO workspaces (
                        workspace_id,
                        revision,
                        schema_version,
                        name,
                        updated_at,
                        document_json
                    )
                    VALUES (?, 0, ?, ?, ?, ?)
                    """,
                    (
                        workspace_id,
                        migrated.document["schema_version"],
                        migrated.document["name"],
                        migrated.document["updated_at"],
                        canonical,
                    ),
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise WorkspaceConflictError(
                f"Workspace {workspace_id!r} already exists."
            ) from exc
        return WorkspaceRecord(document=migrated.document, revision=0)

    def save(
        self,
        document: dict[str, Any],
        expected_revision: int,
    ) -> WorkspaceRecord:
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise WorkspaceConflictError(
                "expected_revision must be a non-negative integer."
            )
        migrated = migrate_workspace(document)
        validate_workspace(migrated.document)
        canonical = _canonical_json(migrated.document)
        workspace_id = migrated.document["workspace_id"]

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT revision FROM workspaces WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise WorkspaceNotFoundError(
                    f"Workspace {workspace_id!r} was not found."
                )
            if row["revision"] != expected_revision:
                connection.rollback()
                raise WorkspaceConflictError(
                    f"Workspace revision conflict: expected {expected_revision}, "
                    f"current {row['revision']}."
                )
            new_revision = expected_revision + 1
            connection.execute(
                """
                UPDATE workspaces
                SET revision = ?,
                    schema_version = ?,
                    name = ?,
                    updated_at = ?,
                    document_json = ?
                WHERE workspace_id = ?
                """,
                (
                    new_revision,
                    migrated.document["schema_version"],
                    migrated.document["name"],
                    migrated.document["updated_at"],
                    canonical,
                    workspace_id,
                ),
            )
            connection.commit()
        return WorkspaceRecord(
            document=migrated.document,
            revision=new_revision,
        )

    def delete(self, workspace_id: str, expected_revision: int) -> None:
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise WorkspaceConflictError(
                "expected_revision must be a non-negative integer."
            )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT revision FROM workspaces WHERE workspace_id = ?",
                (workspace_id,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise WorkspaceNotFoundError(
                    f"Workspace {workspace_id!r} was not found."
                )
            if row["revision"] != expected_revision:
                connection.rollback()
                raise WorkspaceConflictError(
                    f"Workspace revision conflict: expected {expected_revision}, "
                    f"current {row['revision']}."
                )
            connection.execute(
                "DELETE FROM workspaces WHERE workspace_id = ?",
                (workspace_id,),
            )
            connection.commit()

    def clear_all(self) -> int:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute(
                "SELECT COUNT(*) AS total FROM workspaces"
            ).fetchone()["total"]
            connection.execute("DELETE FROM workspaces")
            connection.commit()
        return int(count)

    def _prepare_directory(self) -> None:
        self.database_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self.database_path.parent.chmod(0o700)
        except OSError:
            pass

    def _initialize(self) -> None:
        existed = self.database_path.exists()
        with self._connect() as connection:
            current_version = int(
                connection.execute("PRAGMA user_version").fetchone()[0]
            )
            if current_version > DB_VERSION:
                raise WorkspaceDatabaseVersionError(
                    f"Workspace database version {current_version} is newer than "
                    f"supported version {DB_VERSION}."
                )
            if current_version < DB_VERSION:
                if existed and self.database_path.stat().st_size:
                    self._backup_database(current_version)
                self._migrate_database(connection, current_version)
        try:
            self.database_path.chmod(0o600)
        except OSError:
            pass

    def _migrate_database(
        self,
        connection: sqlite3.Connection,
        current_version: int,
    ) -> None:
        connection.execute("BEGIN IMMEDIATE")
        try:
            if current_version == 0:
                connection.execute(
                    """
                    CREATE TABLE workspaces (
                        workspace_id TEXT PRIMARY KEY,
                        revision INTEGER NOT NULL CHECK (revision >= 0),
                        schema_version TEXT NOT NULL,
                        name TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        document_json TEXT NOT NULL
                    )
                    """
                )
                current_version = 1
            if current_version != DB_VERSION:
                raise WorkspaceDatabaseVersionError(
                    f"No database migration path from {current_version} to "
                    f"{DB_VERSION}."
                )
            connection.execute(f"PRAGMA user_version = {DB_VERSION}")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _backup_database(self, source_version: int) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = self.database_path.with_name(
            f"{self.database_path.name}.v{source_version}.{stamp}.bak"
        )
        shutil.copy2(self.database_path, backup)
        return backup

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=5.0,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        return connection


def default_database_path() -> Path:
    """Return an OS-appropriate per-user application data path."""
    override = os.environ.get("SECURITY_HEADERS_AUDITOR_DATA_DIR")
    if override:
        return Path(override).expanduser() / DATABASE_FILENAME
    home = Path.home()
    if sys.platform == "darwin":
        root = home / "Library" / "Application Support"
    elif os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share"))
    return root / "security-headers-auditor" / DATABASE_FILENAME


def _canonical_json(document: dict[str, Any]) -> str:
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
