"""The default urllib transport against a loopback server. Nothing leaves the machine."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from auth4 import (
    USER_AGENT,
    Auth4ServerClient,
    Auth4TokenError,
    HttpRequest,
    HttpResponse,
    IntrospectionOptions,
    __version__,
    urllib_transport,
)
from conftest import (
    AUDIENCE,
    NOW,
    SERVER_CLIENT_ID,
    SERVER_CLIENT_SECRET,
    TENANT_ID,
    access_claims,
    private_key,
    public_jwk,
    sign,
)

ROUTES: dict[str, tuple[int, dict[str, str], bytes]] = {}
USER_AGENTS: dict[str, str | None] = {}
"""The User-Agent each path was last requested with."""


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        USER_AGENTS[path] = self.headers.get("User-Agent")
        route = ROUTES.get(path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        status, headers, body = route
        if headers.get("x-delay"):
            time.sleep(float(headers["x-delay"]))
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def origin() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        ROUTES.clear()
        USER_AGENTS.clear()


def client_for(origin: str, **options: object) -> Auth4ServerClient:
    issuer = f"{origin}/t/{TENANT_ID}"
    return Auth4ServerClient(
        tenant_id=TENANT_ID,
        issuer=issuer,
        audience=AUDIENCE,
        now=lambda: NOW,
        **options,  # type: ignore[arg-type]
    )


def token_for(origin: str) -> str:
    return sign(access_claims(iss=f"{origin}/t/{TENANT_ID}"))


def serve_jwks(
    status: int = 200, headers: dict[str, str] | None = None, body: bytes | None = None
) -> None:
    jwks = json.dumps({"keys": [public_jwk(private_key(), "key-1")]}).encode()
    ROUTES[f"/t/{TENANT_ID}/.well-known/jwks.json"] = (status, headers or {}, body or jwks)


def test_fetches_keys_over_http(origin: str) -> None:
    serve_jwks()
    assert client_for(origin).validate_access_token(token_for(origin)).subject


def test_redirects_are_not_followed(origin: str) -> None:
    serve_jwks(302, {"Location": "/elsewhere"})
    ROUTES["/elsewhere"] = (
        200,
        {},
        json.dumps({"keys": [public_jwk(private_key(), "key-1")]}).encode(),
    )
    with pytest.raises(Auth4TokenError) as caught:
        client_for(origin).validate_access_token(token_for(origin))
    assert caught.value.code == "jwks_unavailable"


def test_oversized_bodies_are_refused(origin: str) -> None:
    serve_jwks(body=b" " * (256 * 1024 + 10))
    with pytest.raises(Auth4TokenError) as caught:
        client_for(origin).validate_access_token(token_for(origin))
    assert caught.value.code == "jwks_unavailable"


def test_timeouts_are_outages(origin: str) -> None:
    serve_jwks(headers={"x-delay": "0.5"})
    with pytest.raises(Auth4TokenError) as caught:
        client_for(origin, jwks_fetch_timeout=0.1).validate_access_token(token_for(origin))
    assert caught.value.code == "jwks_unavailable"


def test_error_statuses_are_outages(origin: str) -> None:
    serve_jwks(500)
    with pytest.raises(Auth4TokenError) as caught:
        client_for(origin).validate_access_token(token_for(origin))
    assert caught.value.code == "jwks_unavailable"


def test_sends_the_sdk_user_agent_by_default(origin: str) -> None:
    # BUG-AUTH4D-198-1: Cloudflare answers Python-urllib/3.x with 403 error 1010.
    issuer = f"{origin}/t/{TENANT_ID}"
    serve_jwks()
    ROUTES[f"/t/{TENANT_ID}/.well-known/openid-configuration"] = (
        200,
        {},
        json.dumps(
            {
                "issuer": issuer,
                "jwks_uri": f"{issuer}/.well-known/jwks.json",
                "id_token_signing_alg_values_supported": ["RS256"],
                "introspection_endpoint": f"{origin}/oauth/introspect?tenant_id={TENANT_ID}",
            }
        ).encode(),
    )
    claims = access_claims(iss=issuer)
    ROUTES["/oauth/introspect"] = (
        200,
        {},
        json.dumps(
            {
                "active": True,
                "sub": claims["sub"],
                "client_id": claims["client_id"],
                "jti": claims["jti"],
                "tenant_id": TENANT_ID,
            }
        ).encode(),
    )
    client = client_for(
        origin,
        introspection=IntrospectionOptions(
            client_id=SERVER_CLIENT_ID, client_secret=SERVER_CLIENT_SECRET
        ),
    )
    client.discover()
    assert client.validate_access_token(sign(claims)).subject == claims["sub"]
    assert USER_AGENT == f"auth4-python/{__version__}"
    assert USER_AGENTS == {
        f"/t/{TENANT_ID}/.well-known/openid-configuration": USER_AGENT,
        f"/t/{TENANT_ID}/.well-known/jwks.json": USER_AGENT,
        "/oauth/introspect": USER_AGENT,
    }


def test_user_agent_names_the_packaged_version() -> None:
    pyproject = (Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    assert f'\nversion = "{__version__}"\n' in pyproject


def test_custom_transports_see_the_user_agent(origin: str) -> None:
    serve_jwks()
    seen: list[HttpRequest] = []

    def transport(request: HttpRequest) -> HttpResponse:
        seen.append(request)
        return urllib_transport(request)

    client_for(origin, transport=transport).validate_access_token(token_for(origin))
    assert [request.headers["User-Agent"] for request in seen] == [USER_AGENT]


def test_default_transport_keeps_a_caller_user_agent(origin: str) -> None:
    serve_jwks()
    path = f"/t/{TENANT_ID}/.well-known/jwks.json"
    for headers, expected in (({}, USER_AGENT), ({"user-agent": "game-server/2"}, "game-server/2")):
        urllib_transport(HttpRequest("GET", f"{origin}{path}", headers, None, 1.0))
        assert USER_AGENTS[path] == expected
