"""The HTTP seam. The SDK only ever sends requests to URLs derived from the configured issuer."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from ._version import __version__

MAX_RESPONSE_BYTES = 256 * 1024

USER_AGENT = f"auth4-python/{__version__}"
"""Sent on every discovery, JWKS and introspection request. Cloudflare blocks the urllib default
(``Python-urllib/3.x``) on the auth4.dev hosts with 403 error 1010 (BUG-AUTH4D-198-1)."""


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes | None
    timeout: float
    """Seconds."""

    def __repr__(self) -> str:
        # Headers can carry the introspection credentials and the body a token.
        return f"HttpRequest(method={self.method!r}, url={self.url!r})"


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


Transport = Callable[[HttpRequest], HttpResponse]
"""Sends one request. Injectable for tests and custom HTTP stacks. It must not follow redirects,
and should raise on network errors and timeouts. Bodies over 256 KiB are refused either way."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        raise urllib.error.HTTPError(req.full_url, code, "Redirects are not followed.", headers, fp)


_opener = urllib.request.build_opener(_NoRedirects())


def urllib_transport(request: HttpRequest) -> HttpResponse:
    """The default transport: the standard library, no redirects, a bounded body."""
    headers = dict(request.headers)
    if not any(name.lower() == "user-agent" for name in headers):
        headers["User-Agent"] = USER_AGENT
    prepared = urllib.request.Request(
        request.url, data=request.body, headers=headers, method=request.method
    )
    try:
        response = _opener.open(prepared, timeout=request.timeout)
    except urllib.error.HTTPError as error:
        # Non-2xx answers are returned, not raised; the caller decides what they mean.
        error.close()
        return HttpResponse(status=error.code, body=b"")
    with response:
        body = response.read(MAX_RESPONSE_BYTES + 1)
        return HttpResponse(status=response.status, body=body, headers=dict(response.headers))


def send_for_json(transport: Transport, request: HttpRequest, what: str) -> bytes:
    """Sends ``request`` and returns a 2xx body within the size limit. Raises on anything else."""
    response = transport(request)
    if not 200 <= response.status < 300:
        raise RuntimeError(f"{what} returned HTTP {response.status}.")
    if len(response.body) > MAX_RESPONSE_BYTES:
        raise RuntimeError(f"{what} response exceeded its size limit.")
    return response.body
