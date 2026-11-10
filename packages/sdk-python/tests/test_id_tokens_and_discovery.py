from __future__ import annotations

import pytest

from auth4 import Auth4DiscoveryError, Auth4TokenError, IntrospectionOptions
from conftest import (
    AUDIENCE,
    DROP,
    INTROSPECTION_URL,
    ISSUER,
    JWKS_URL,
    NOW,
    SERVER_CLIENT_ID,
    SERVER_CLIENT_SECRET,
    FakeServer,
    access_claims,
    id_claims,
    sign,
)

NONCE = "nonce-0123456789abcdef"


def test_valid_id_token(server: FakeServer) -> None:
    token = server.client().validate_id_token(
        sign(id_claims(), typ="JWT"), AUDIENCE, expected_nonce=NONCE
    )
    assert token.subject == "usr_player0000000001"
    assert token.client_id == AUDIENCE
    assert token.auth_time == NOW - 10
    assert token.email == "player@example.test" and token.email_verified is True
    assert token.nonce == NONCE


def test_optional_id_claims(server: FakeServer) -> None:
    claims = id_claims(nonce=DROP, email=DROP, email_verified=DROP)
    token = server.client().validate_id_token(sign(claims, typ="JWT"), AUDIENCE)
    assert token.nonce is None and token.email is None and token.email_verified is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "cli_webclient00000002"},
        {"token_use": "access"},
        {"auth_time": DROP},
        {"auth_time": 0},
        {"nonce": "short"},
        {"email": "not-an-email"},
        {"email": DROP},
        {"email_verified": "true"},
        {"exp": NOW + 301},
        {"scope": "openid"},
        {"auth4_guest": True},
    ],
)
def test_id_contract_violations(server: FakeServer, overrides: dict) -> None:
    with pytest.raises(Auth4TokenError):
        server.client().validate_id_token(sign(id_claims(**overrides), typ="JWT"), AUDIENCE)


def test_nonce_must_match_when_expected(server: FakeServer) -> None:
    client = server.client()
    with pytest.raises(Auth4TokenError):
        client.validate_id_token(sign(id_claims(), typ="JWT"), AUDIENCE, expected_nonce=NONCE + "x")
    with pytest.raises(Auth4TokenError):
        client.validate_id_token(
            sign(id_claims(nonce=DROP), typ="JWT"), AUDIENCE, expected_nonce=NONCE
        )


def test_token_kinds_cannot_stand_in_for_each_other(server: FakeServer) -> None:
    client = server.client()
    # An ID token signed as an access token type, and vice versa.
    with pytest.raises(Auth4TokenError):
        client.validate_access_token(sign(id_claims(), typ="JWT"))
    with pytest.raises(Auth4TokenError):
        client.validate_access_token(sign(id_claims(), typ="at+jwt"))
    with pytest.raises(Auth4TokenError):
        client.validate_id_token(sign(access_claims(), typ="at+jwt"), AUDIENCE)
    with pytest.raises(Auth4TokenError):
        client.validate_id_token(sign(access_claims(), typ="JWT"), AUDIENCE)


def test_id_client_id_is_checked(server: FakeServer) -> None:
    with pytest.raises(ValueError):
        server.client().validate_id_token(sign(id_claims(), typ="JWT"), "web")


def discovery_document(**overrides: object) -> dict:
    document = {
        "issuer": ISSUER,
        "jwks_uri": JWKS_URL,
        "token_endpoint": "https://auth.example.test/oauth/token",
        "userinfo_endpoint": "https://auth.example.test/oauth/userinfo",
        "id_token_signing_alg_values_supported": ["RS256"],
        "introspection_endpoint": INTROSPECTION_URL,
    }
    document.update(overrides)
    return document


def test_discovery(server: FakeServer) -> None:
    server.discovery = discovery_document()
    discovery = server.client().discover()
    assert discovery.issuer == ISSUER
    assert discovery.jwks_uri == JWKS_URL
    assert discovery.token_endpoint == "https://auth.example.test/oauth/token"
    assert discovery.introspection_endpoint == INTROSPECTION_URL


@pytest.mark.parametrize(
    "overrides",
    [
        {"issuer": "https://evil.example.test/t/ten_abcdefghijklmnop"},
        {"jwks_uri": "https://evil.example.test/jwks.json"},
        {"id_token_signing_alg_values_supported": ["HS256"]},
        {"id_token_signing_alg_values_supported": DROP},
    ],
)
def test_discovery_mismatches(server: FakeServer, overrides: dict) -> None:
    document = discovery_document(**overrides)
    server.discovery = {name: value for name, value in document.items() if value is not DROP}
    with pytest.raises(Auth4DiscoveryError):
        server.client().discover()


def test_discovery_checks_introspection_endpoint(server: FakeServer) -> None:
    server.discovery = discovery_document(introspection_endpoint=DROP)
    server.discovery.pop("introspection_endpoint")
    assert server.client().discover().introspection_endpoint is None
    introspecting = server.client(
        introspection=IntrospectionOptions(
            client_id=SERVER_CLIENT_ID, client_secret=SERVER_CLIENT_SECRET
        )
    )
    with pytest.raises(Auth4DiscoveryError):
        introspecting.discover()


def test_discovery_unavailable(server: FakeServer) -> None:
    with pytest.raises(Auth4DiscoveryError):
        server.client().discover()
