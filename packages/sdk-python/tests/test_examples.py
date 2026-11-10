"""Runs examples/python against a loopback auth origin that serves discovery and JWKS from local
fixtures, through the SDK's default transport."""

from __future__ import annotations

import importlib.util
import json
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("django")

from conftest import AUDIENCE, TENANT_ID, access_claims, private_key, public_jwk, sign  # noqa: E402

EXAMPLES = Path(__file__).parents[3] / "examples" / "python"
# The public SDK mirror (AUTH4D-478) carries no examples/ directory.
if not EXAMPLES.is_dir():
    pytest.skip("examples/python is not in this checkout", allow_module_level=True)


class Handler(BaseHTTPRequestHandler):
    origin = ""

    def do_GET(self) -> None:  # noqa: N802
        issuer = f"{self.origin}/t/{TENANT_ID}"
        documents = {
            f"/t/{TENANT_ID}/.well-known/jwks.json": {"keys": [public_jwk(private_key(), "key-1")]},
            f"/t/{TENANT_ID}/.well-known/openid-configuration": {
                "issuer": issuer,
                "jwks_uri": f"{issuer}/.well-known/jwks.json",
                "id_token_signing_alg_values_supported": ["RS256"],
            },
        }
        document = documents.get(self.path)
        body = json.dumps(document).encode()
        self.send_response(200 if document else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def auth_origin(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Handler.origin = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("AUTH4_TENANT_ID", TENANT_ID)
    monkeypatch.setenv("AUTH4_AUTH_ORIGIN", Handler.origin)
    monkeypatch.setenv("AUTH4_AUDIENCE", AUDIENCE)
    try:
        yield Handler.origin
    finally:
        server.shutdown()
        server.server_close()


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, EXAMPLES / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def bearer(origin: str, **claims: object) -> dict[str, str]:
    token = sign(access_claims(iss=f"{origin}/t/{TENANT_ID}", **claims), key=private_key())
    return {"Authorization": f"Bearer {token}"}


def fresh(origin: str, **claims: object) -> dict[str, str]:
    import time

    now = int(time.time())
    return bearer(origin, iat=now, exp=now + 300, **claims)


def test_fastapi_example(auth_origin: str) -> None:
    from fastapi.testclient import TestClient

    example = load("fastapi_app")
    with TestClient(example.app) as client:  # runs the startup discovery check
        assert client.get("/profile").status_code == 401
        response = client.get("/profile", headers=fresh(auth_origin, auth4_meta={"level": 3}))
        assert response.status_code == 200
        assert response.json() == {
            "player": "usr_player0000000001",
            "guest": False,
            "roles": [],
            "level": 3,
        }
        assert client.post("/moderation/kick", headers=fresh(auth_origin)).status_code == 403
        kick = client.post(
            "/moderation/kick", headers=fresh(auth_origin, auth4_roles=["moderator"])
        )
        assert kick.status_code == 200
        assert (
            client.post("/trade", headers=fresh(auth_origin, auth4_guest=True)).status_code == 403
        )
        assert client.post("/trade", headers=fresh(auth_origin)).status_code == 200


def test_django_example(auth_origin: str) -> None:
    import django
    from django.test import Client, override_settings

    load("django_app")
    django.setup()
    config = {"TENANT_ID": TENANT_ID, "AUTH_ORIGIN": auth_origin, "AUDIENCE": AUDIENCE}
    with override_settings(AUTH4=config, ROOT_URLCONF="django_app"):
        client = Client()
        assert client.get("/profile").status_code == 401
        response = client.get("/profile", headers=fresh(auth_origin))
        assert response.status_code == 200
        assert response.json() == {"player": "usr_player0000000001", "guest": False}
        assert client.post("/moderation/kick", headers=fresh(auth_origin)).status_code == 403
        roles = fresh(auth_origin, auth4_roles=["moderator"])
        assert client.post("/moderation/kick", headers=roles).status_code == 200
        guest = fresh(auth_origin, auth4_guest=True)
        assert client.post("/trade", headers=guest).status_code == 403
        assert client.post("/trade", headers=fresh(auth_origin)).status_code == 200
        assert client.get("/trade", headers=fresh(auth_origin)).status_code == 405
