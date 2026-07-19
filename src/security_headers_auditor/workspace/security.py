"""Authorization checks for the loopback workspace API."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from hmac import compare_digest
from typing import Mapping


MAX_API_BODY_BYTES = 2 * 1024 * 1024
BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class WorkspaceAuthorizationError(PermissionError):
    """Raised when a loopback API request violates the local trust boundary."""


class WorkspaceRequestError(ValueError):
    """Raised when an API request is malformed or exceeds resource limits."""


@dataclass(frozen=True)
class LoopbackRequestGuard:
    token: str
    host: str
    port: int

    @classmethod
    def create(
        cls,
        host: str = "127.0.0.1",
        port: int = 8766,
    ) -> "LoopbackRequestGuard":
        if host != "127.0.0.1":
            raise ValueError("The baseline workspace must bind to 127.0.0.1.")
        if isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("Workspace port must be between 1 and 65535.")
        return cls(token=secrets.token_urlsafe(32), host=host, port=port)

    @property
    def origin(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def expected_host(self) -> str:
        return f"{self.host}:{self.port}"

    def authorize(
        self,
        method: str,
        headers: Mapping[str, str],
        content_length: int | None = None,
    ) -> None:
        """Reject cross-origin, tokenless, or oversized API requests."""
        normalized = {key.lower(): value.strip() for key, value in headers.items()}
        if normalized.get("host") != self.expected_host:
            raise WorkspaceAuthorizationError("Request Host is not authorized.")

        authorization = normalized.get("authorization", "")
        scheme, separator, candidate = authorization.partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not compare_digest(candidate, self.token)
        ):
            raise WorkspaceAuthorizationError(
                "A valid workspace session token is required."
            )

        origin = normalized.get("origin")
        if origin is not None and origin != self.origin:
            raise WorkspaceAuthorizationError("Request Origin is not authorized.")
        if method.upper() in BODY_METHODS and origin != self.origin:
            raise WorkspaceAuthorizationError(
                "State-changing requests require the workspace Origin."
            )

        fetch_site = normalized.get("sec-fetch-site")
        if fetch_site is not None and fetch_site not in {"same-origin", "none"}:
            raise WorkspaceAuthorizationError(
                "Cross-site browser requests are not authorized."
            )

        if method.upper() in BODY_METHODS:
            content_type = normalized.get("content-type", "")
            media_type = content_type.split(";", 1)[0].strip().lower()
            if media_type != "application/json":
                raise WorkspaceRequestError(
                    "State-changing requests require application/json."
                )

        if content_length is not None:
            if content_length < 0:
                raise WorkspaceRequestError("Content-Length cannot be negative.")
            if content_length > MAX_API_BODY_BYTES:
                raise WorkspaceRequestError(
                    f"Request body exceeds {MAX_API_BODY_BYTES} bytes."
                )
