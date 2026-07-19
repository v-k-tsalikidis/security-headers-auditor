"""Deterministic local server used only for browser QA."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path
from unittest.mock import patch

from security_headers_auditor.workspace.repository import WorkspaceRepository
from security_headers_auditor.workspace.server import create_workspace_server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8766)
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="sha-browser-qa-") as directory:
        repository = WorkspaceRepository(
            Path(directory) / "workspace.sqlite3"
        )
        with patch(
            "security_headers_auditor.workspace.security.secrets.token_urlsafe",
            return_value="browser-qa-token",
        ):
            server = create_workspace_server(
                repository,
                port=arguments.port,
                allow_private_targets=True,
            )
        server.serve_forever(open_browser=False)


if __name__ == "__main__":
    main()
