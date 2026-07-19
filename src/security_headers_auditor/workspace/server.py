"""Loopback-only HTTP server for the local workspace interface."""

from __future__ import annotations

import json
import mimetypes
import webbrowser
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

from .repository import (
    WorkspaceConflictError,
    WorkspaceNotFoundError,
    WorkspaceRepository,
    WorkspaceRepositoryError,
)
from .schema import WorkspaceValidationError
from .security import (
    MAX_API_BODY_BYTES,
    LoopbackRequestGuard,
    WorkspaceAuthorizationError,
    WorkspaceRequestError,
)
from .service import WorkspaceService


@dataclass(frozen=True)
class WorkspaceServer:
    httpd: ThreadingHTTPServer
    guard: LoopbackRequestGuard

    @property
    def url(self) -> str:
        return f"{self.guard.origin}/#token={self.guard.token}"

    def serve_forever(self, open_browser: bool = True) -> None:
        if open_browser:
            webbrowser.open(self.url, new=2)
        try:
            self.httpd.serve_forever()
        finally:
            self.httpd.server_close()


def create_workspace_server(
    repository: WorkspaceRepository,
    port: int = 8766,
    allow_private_targets: bool = False,
) -> WorkspaceServer:
    service = WorkspaceService(
        repository,
        allow_private_targets=allow_private_targets,
    )
    httpd = ThreadingHTTPServer(
        ("127.0.0.1", port),
        BaseHTTPRequestHandler,
    )
    actual_port = int(httpd.server_address[1])
    guard = LoopbackRequestGuard.create(port=actual_port)
    handler = _handler_factory(service, guard)
    httpd.RequestHandlerClass = handler
    httpd.daemon_threads = True
    return WorkspaceServer(httpd=httpd, guard=guard)


def _handler_factory(
    service: WorkspaceService,
    guard: LoopbackRequestGuard,
):
    class WorkspaceRequestHandler(BaseHTTPRequestHandler):
        server_version = "SecurityHeadersAuditorWorkspace"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            path = urlparse(self.path).path
            if path.startswith("/api/"):
                self._handle_api("GET", path)
                return
            self._serve_static(path)

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._handle_api("POST", urlparse(self.path).path)

        def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._handle_api("PUT", urlparse(self.path).path)

        def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._handle_api("DELETE", urlparse(self.path).path)

        def do_OPTIONS(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._json_error(
                HTTPStatus.METHOD_NOT_ALLOWED,
                "Cross-origin preflight is not supported.",
            )

        def log_message(self, format: str, *args: object) -> None:
            del format, args

        def _handle_api(self, method: str, path: str) -> None:
            try:
                content_length = self._content_length()
                guard.authorize(method, self.headers, content_length)
                body = self._read_json(content_length) if method != "GET" else None
                status, payload = self._route_api(method, path, body)
                self._json(status, payload)
            except WorkspaceAuthorizationError as exc:
                self._json_error(HTTPStatus.FORBIDDEN, str(exc))
            except (WorkspaceRequestError, WorkspaceValidationError, ValueError) as exc:
                self._json_error(HTTPStatus.BAD_REQUEST, str(exc))
            except WorkspaceNotFoundError as exc:
                self._json_error(HTTPStatus.NOT_FOUND, str(exc))
            except WorkspaceConflictError as exc:
                self._json_error(HTTPStatus.CONFLICT, str(exc))
            except WorkspaceRepositoryError as exc:
                self._json_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

        def _route_api(
            self,
            method: str,
            path: str,
            body: dict[str, Any] | None,
        ) -> tuple[HTTPStatus, dict[str, Any]]:
            segments = [
                unquote(segment)
                for segment in PurePosixPath(path).parts
                if segment not in {"/", ""}
            ]
            if segments[:2] != ["api", "v1"]:
                raise WorkspaceNotFoundError("Unknown API route.")
            tail = segments[2:]

            if method == "GET" and tail == ["bootstrap"]:
                return HTTPStatus.OK, service.bootstrap()
            if method == "GET" and tail == ["workspaces"]:
                return HTTPStatus.OK, {
                    "workspaces": list(service.repository.list_workspaces())
                }
            if method == "POST" and tail == ["workspaces"]:
                return HTTPStatus.CREATED, service.create(_require_object(body))
            if len(tail) >= 2 and tail[0] == "workspaces":
                workspace_id = tail[1]
                if method == "GET" and len(tail) == 2:
                    return HTTPStatus.OK, service.get(workspace_id)
                if method == "PUT" and len(tail) == 2:
                    payload = _require_object(body)
                    return HTTPStatus.OK, service.save(
                        workspace_id,
                        _require_object(payload.get("document")),
                        _require_revision(payload),
                    )
                if method == "DELETE" and len(tail) == 2:
                    payload = _require_object(body)
                    service.delete(workspace_id, _require_revision(payload))
                    return HTTPStatus.OK, {"deleted": workspace_id}
                if method == "POST" and tail[2:] == ["run"]:
                    payload = _require_object(body)
                    target_id = payload.get("target_id")
                    if target_id is not None and (
                        not isinstance(target_id, str) or not target_id
                    ):
                        raise WorkspaceRequestError(
                            "target_id must be a non-empty string when provided."
                        )
                    return HTTPStatus.OK, service.run(
                        workspace_id,
                        _require_revision(payload),
                        target_id=target_id,
                    )
                if method == "POST" and tail[2:] == ["baseline-candidate"]:
                    payload = _require_object(body)
                    return HTTPStatus.OK, service.create_candidate_baseline(
                        workspace_id,
                        _require_revision(payload),
                    )
                if method == "PUT" and tail[2:] == ["approved-baseline"]:
                    payload = _require_object(body)
                    return HTTPStatus.OK, service.approve_baseline(
                        workspace_id,
                        _require_object(payload.get("candidate")),
                        _require_revision(payload),
                    )
                if method == "GET" and len(tail) == 4 and tail[2] == "reports":
                    return HTTPStatus.OK, service.export_current_report(
                        workspace_id,
                        tail[3],
                    )
            raise WorkspaceNotFoundError("Unknown API route.")

        def _serve_static(self, path: str) -> None:
            relative = "index.html" if path in {"", "/"} else path.lstrip("/")
            if ".." in PurePosixPath(relative).parts:
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            root = files("security_headers_auditor").joinpath("workspace_static")
            resource = root.joinpath(relative)
            if not resource.is_file():
                resource = root.joinpath("index.html")
            if not resource.is_file():
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            content = resource.read_bytes()
            media_type = mimetypes.guess_type(relative)[0] or "application/octet-stream"
            self.send_response(HTTPStatus.OK)
            self._security_headers()
            self.send_header("Content-Type", f"{media_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def _content_length(self) -> int | None:
            raw = self.headers.get("Content-Length")
            if raw is None:
                return None
            try:
                value = int(raw)
            except ValueError as exc:
                raise WorkspaceRequestError(
                    "Content-Length must be an integer."
                ) from exc
            if value > MAX_API_BODY_BYTES:
                raise WorkspaceRequestError(
                    f"Request body exceeds {MAX_API_BODY_BYTES} bytes."
                )
            return value

        def _read_json(self, content_length: int | None) -> dict[str, Any]:
            if content_length is None:
                raise WorkspaceRequestError("Request body requires Content-Length.")
            raw = self.rfile.read(content_length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise WorkspaceRequestError("Request body must be UTF-8.") from exc
            except json.JSONDecodeError as exc:
                raise WorkspaceRequestError(
                    f"Request body is not valid JSON: line {exc.lineno}, "
                    f"column {exc.colno}."
                ) from exc
            return _require_object(payload)

        def _json(
            self,
            status: HTTPStatus,
            payload: dict[str, Any],
        ) -> None:
            body = (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self.send_response(status)
            self._security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json_error(self, status: HTTPStatus, message: str) -> None:
            self._json(status, {"error": message, "status": int(status)})

        def _security_headers(self) -> None:
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", (
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; font-src 'none'; "
                "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
            ))
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", (
                "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
            ))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")

    return WorkspaceRequestHandler


def _require_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise WorkspaceRequestError("Request body must be a JSON object.")
    return value


def _require_revision(payload: dict[str, Any]) -> int:
    value = payload.get("revision")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise WorkspaceRequestError(
            "revision must be a non-negative integer."
        )
    return value
