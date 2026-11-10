from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from auth4 import AccessToken, HttpRequest, HttpResponse  # noqa: E402
from auth4.fastapi import Auth4Bearer  # noqa: E402
from conftest import FakeServer, access_claims, sign  # noqa: E402


def make_app(server: FakeServer) -> TestClient:
    auth4 = server.client()
    player = Auth4Bearer(auth4)
    moderator = Auth4Bearer(auth4, any_role=["moderator", "admin"])
    upgraded = Auth4Bearer(auth4, allow_guests=False)
    emailed = Auth4Bearer(auth4, scopes=["email"])
    app = FastAPI()

    @app.get("/profile")
    def profile(token: AccessToken = Depends(player)) -> dict:
        return {"player": token.subject, "guest": token.is_guest}

    @app.post("/kick")
    def kick(token: AccessToken = Depends(moderator)) -> dict:
        return {"by": token.subject}

    @app.post("/trade")
    async def trade(token: AccessToken = Depends(upgraded)) -> dict:
        return {"ok": True}

    @app.get("/email")
    def email(token: AccessToken = Depends(emailed)) -> dict:
        return {"ok": True}

    return TestClient(app)


def bearer(**claims: object) -> dict:
    return {"Authorization": f"Bearer {sign(access_claims(**claims))}"}


def test_valid_token(server: FakeServer) -> None:
    response = make_app(server).get("/profile", headers=bearer())
    assert response.status_code == 200
    assert response.json() == {"player": "usr_player0000000001", "guest": False}


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic x"}]
)
def test_missing_or_invalid_tokens_get_401(server: FakeServer, headers: dict) -> None:
    response = make_app(server).get("/profile", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Bearer realm="auth4"'
    assert response.json() == {"detail": "unauthorized"}


def test_outage_gets_503(server: FakeServer) -> None:
    server.jwks_status = 500
    response = make_app(server).get("/profile", headers=bearer())
    assert response.status_code == 503
    assert response.headers["retry-after"] == "5"


def test_roles(server: FakeServer) -> None:
    app = make_app(server)
    assert app.post("/kick", headers=bearer()).status_code == 403
    assert app.post("/kick", headers=bearer(auth4_roles=["tester"])).status_code == 403
    assert app.post("/kick", headers=bearer(auth4_roles=["moderator"])).status_code == 200


def test_guests(server: FakeServer) -> None:
    app = make_app(server)
    assert app.get("/profile", headers=bearer(auth4_guest=True)).json()["guest"] is True
    assert app.post("/trade", headers=bearer(auth4_guest=True)).status_code == 403
    assert app.post("/trade", headers=bearer(auth4_guest=False)).status_code == 200


def test_scopes(server: FakeServer) -> None:
    app = make_app(server)
    assert app.get("/email", headers=bearer()).status_code == 403
    assert app.get("/email", headers=bearer(scope="openid email")).status_code == 200


def test_openapi_documents_bearer_scheme(server: FakeServer) -> None:
    schema = make_app(server).get("/openapi.json").json()
    assert schema["components"]["securitySchemes"]["auth4"] == {"type": "http", "scheme": "bearer"}


def test_runs_off_the_event_loop(server: FakeServer) -> None:
    # The dependency is synchronous, so FastAPI runs it (and any key fetch) in its threadpool.
    import threading

    threads = []

    def transport(request: HttpRequest) -> HttpResponse:
        threads.append(threading.current_thread().name)
        return server(request)

    player = Auth4Bearer(server.client(transport=transport))
    app = FastAPI()

    @app.get("/")
    async def root(token: AccessToken = Depends(player)) -> dict:
        return {"loop": threading.current_thread().name}

    response = TestClient(app).get("/", headers=bearer())
    assert response.status_code == 200
    assert threads and threads[0] != response.json()["loop"]
