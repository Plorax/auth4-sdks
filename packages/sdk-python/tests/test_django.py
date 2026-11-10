from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("django")

import django  # noqa: E402
from django.conf import settings  # noqa: E402

if not settings.configured:
    settings.configure(DEBUG=False, ALLOWED_HOSTS=["testserver"], ROOT_URLCONF=__name__, AUTH4={})
    django.setup()

from django.core.exceptions import ImproperlyConfigured  # noqa: E402
from django.http import JsonResponse  # noqa: E402
from django.test import RequestFactory, override_settings  # noqa: E402

import auth4.django as auth4_django  # noqa: E402
from auth4.django import auth4_required, get_client  # noqa: E402
from conftest import AUDIENCE, ISSUER, TENANT_ID, FakeServer, access_claims, sign  # noqa: E402

urlpatterns: list = []


@auth4_required()
def profile(request):
    return JsonResponse({"player": request.auth4.subject})


@auth4_required(any_role=["moderator"], allow_guests=False)
def kick(request):
    return JsonResponse({"ok": True})


@auth4_required(scopes=["email"])
async def email(request):
    return JsonResponse({"ok": True})


@pytest.fixture
def configured(server: FakeServer):
    with override_settings(AUTH4={"TENANT_ID": TENANT_ID, "ISSUER": ISSUER, "AUDIENCE": AUDIENCE}):
        # Swap the settings-built client's transport for the fake server.
        client = get_client()
        fake = server.client()
        auth4_django._client = fake
        yield client
    assert auth4_django._client is None


def call(view, **claims: object):
    request = RequestFactory().get(
        "/", HTTP_AUTHORIZATION=f"Bearer {sign(access_claims(**claims))}"
    )
    response = view(request)
    if asyncio.iscoroutine(response):
        response = asyncio.run(response)
    return response


def test_client_from_settings(configured) -> None:
    assert configured.issuer == ISSUER
    assert configured.audience == AUDIENCE


def test_auth_origin_and_introspection_settings() -> None:
    config = {
        "TENANT_ID": TENANT_ID,
        "AUTH_ORIGIN": "https://auth.example.test",
        "AUDIENCE": AUDIENCE,
        "INTROSPECTION": {"CLIENT_ID": "cli_serverclient00001", "CLIENT_SECRET": "s" * 40},
    }
    with override_settings(AUTH4=config):
        client = get_client()
        assert client.issuer == ISSUER
        assert (
            client.introspection_url
            == f"https://auth.example.test/oauth/introspect?tenant_id={TENANT_ID}"
        )


def test_bad_settings_are_improperly_configured() -> None:
    with override_settings(AUTH4={"TENANT_ID": TENANT_ID, "AUDIENCE": AUDIENCE}):
        with pytest.raises(ImproperlyConfigured):
            get_client()


def test_valid_token(configured) -> None:
    response = call(profile)
    assert response.status_code == 200
    assert response.content == b'{"player": "usr_player0000000001"}'


def test_missing_and_invalid_tokens_get_401(configured) -> None:
    for request in (
        RequestFactory().get("/"),
        RequestFactory().get("/", HTTP_AUTHORIZATION="Bearer nope"),
    ):
        response = profile(request)
        assert response.status_code == 401
        assert response["WWW-Authenticate"] == 'Bearer realm="auth4"'
        assert response["Cache-Control"] == "no-store"
        assert response.content == b'{"error": "unauthorized"}'


def test_outage_gets_503(configured, server: FakeServer) -> None:
    server.jwks_status = 500
    response = call(profile)
    assert response.status_code == 503
    assert response["Retry-After"] == "5"


def test_roles_and_guests(configured) -> None:
    assert call(kick).status_code == 403
    assert call(kick, auth4_roles=["moderator"], auth4_guest=True).status_code == 403
    assert call(kick, auth4_roles=["moderator"]).status_code == 200


def test_async_views(configured) -> None:
    assert call(email).status_code == 403
    assert call(email, scope="openid email").status_code == 200
