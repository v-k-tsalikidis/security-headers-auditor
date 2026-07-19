"""Deterministic localhost server for manual CLI and browser QA."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


FIXTURES = Path(__file__).parent / "fixtures"
ROUTES = {
    "/api": "api",
    "/app": "app",
    "/brochure": "brochure",
    "/hostile": "hostile",
}


def load_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / f"{name}_headers.json").read_text(encoding="utf-8"))


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "SecurityHeadersAuditorFixture/0.3"

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._respond(include_body=False)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._respond(include_body=True)

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def _respond(self, include_body: bool) -> None:
        route = urlparse(self.path).path
        fixture_name = ROUTES.get(route)
        if fixture_name is None:
            self.send_error(404, "Use /api, /app, /brochure, or /hostile")
            return

        fixture = load_fixture(fixture_name)
        body = f"fixture:{fixture_name}\n".encode()
        self.send_response(int(fixture["status_code"]))
        for name, value in dict(fixture["headers"]).items():
            self.send_header(str(name), str(value))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), FixtureHandler)
    print(f"Fixture server: http://{args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
