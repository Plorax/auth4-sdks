from __future__ import annotations

import json

import pytest

from auth4 import (
    Auth4ServerClient,
    Auth4TokenError,
    has_any_role,
    has_role,
    issuer_for,
    parse_bearer_token,
)
from conftest import (
    AUDIENCE,
    DROP,
    ISSUER,
    NOW,
    OTHER_TENANT_ID,
    TENANT_ID,
    FakeServer,
    access_claims,
    b64url,
    fresh_key,
    sign,
)


def invalid(client: Auth4ServerClient, token: str) -> None:
    with pytest.raises(Auth4TokenError) as caught:
        client.validate_access_token(token)
    assert caught.value.code == "invalid_token"
    assert not caught.value.is_outage


def test_valid_token(server: FakeServer) -> None:
    token = server.client().validate_access_token(sign(access_claims()))
    assert token.subject == "usr_player0000000001"
    assert token.tenant_id == TENANT_ID
    assert token.issuer == ISSUER
    assert token.audience == AUDIENCE
    assert token.client_id == AUDIENCE
    assert token.scopes == ("openid", "profile")
    assert token.has_scope("profile") and not token.has_scope("email")
    assert token.session_id == "ses_session000000001"
    assert token.expires_at == NOW + 300
    assert not token.is_guest
    assert token.roles == ()
    assert dict(token.metadata) == {}


def test_guest_roles_and_metadata(server: FakeServer) -> None:
    claims = access_claims(
        auth4_guest=True,
        auth4_roles=["moderator", "tester"],
        auth4_meta={"level": 7, "region": "eu", "beta": False, "note": None},
    )
    token = server.client().validate_access_token(sign(claims))
    assert token.is_guest
    assert token.roles == ("moderator", "tester")
    assert token.has_role("moderator") and not token.has_role("Moderator")
    assert token.has_any_role(["admin", "tester"]) and not token.has_any_role([])
    assert has_role(token, "tester") and has_any_role(token, ["moderator"])
    assert token.metadata == {"level": 7, "region": "eu", "beta": False, "note": None}
    with pytest.raises(TypeError):
        token.metadata["level"] = 8  # type: ignore[index]


def test_player_name_claim(server: FakeServer) -> None:
    # AUTH4D-324: projects can opt in to the player's Name#1234 in access tokens.
    server.client().validate_access_token(sign(access_claims(name="Ace#0427")))


def test_upgraded_guest_is_not_a_guest(server: FakeServer) -> None:
    assert (
        not server.client().validate_access_token(sign(access_claims(auth4_guest=False))).is_guest
    )


def test_authorization_header(server: FakeServer) -> None:
    client = server.client()
    token = sign(access_claims())
    assert client.validate_authorization_header(f"Bearer {token}").subject == "usr_player0000000001"
    assert client.validate_authorization_header(f"bearer {token}").subject == "usr_player0000000001"
    for header in (
        None,
        "",
        token,
        f"Basic {token}",
        f"Bearer {token} x",
        f"Bearer {token},x",
        f"Bearer {token}\n",
    ):
        with pytest.raises(Auth4TokenError):
            client.validate_authorization_header(header)


def test_parse_bearer_token() -> None:
    assert parse_bearer_token("Bearer abc") == "abc"
    assert parse_bearer_token("Bearer  abc") is None
    assert parse_bearer_token("Bearer abc\n") is None
    assert parse_bearer_token("Bearer " + "a" * 20_000) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"exp": NOW},
        {"exp": NOW - 1, "iat": NOW - 301 + 2},
        {"nbf": NOW + 1},
        {"iat": NOW, "exp": NOW + 301},
        {"iat": NOW + 300, "exp": NOW + 300},
        {"aud": "cli_webclient00000002"},
        {"aud": [AUDIENCE]},
        {"aud": "urn:auth4:management"},
        {"iss": f"https://auth.example.test/t/{OTHER_TENANT_ID}"},
        {"iss": "https://evil.example.test/t/" + TENANT_ID},
        {"tenant_id": OTHER_TENANT_ID},
        {"token_use": "id"},
        {"token_use": DROP},
        {"jti": DROP},
        {"jti": "token1"},
        {"sub": "player"},
        {"client_id": "web"},
        {"scope": ""},
        {"scope": "openid openid"},
        {"scope": "OpenID"},
        {"sid": "nope"},
        {"exp": float(NOW + 300)},
        {"exp": True},
        {"iat": "1800000000"},
        {"auth4_guest": "true"},
        {"auth4_guest": 1},
        {"auth4_roles": []},
        {"auth4_roles": ["a", "a"]},
        {"auth4_roles": ["Admin"]},
        {"auth4_roles": [f"r{i}" for i in range(21)]},
        {"auth4_meta": {}},
        {"auth4_meta": {"x": {"y": 1}}},
        {"auth4_meta": {"x": [1]}},
        {"auth4_meta": {"sub": "x"}},
        {"auth4_meta": {"auth4_x": 1}},
        {"auth4_meta": {"x": "y" * 257}},
        {"auth4_meta": {f"k{i}": 1 for i in range(33)}},
        {"auth4_meta": {f"k{i}": "y" * 200 for i in range(11)}},
        {"role": "admin"},
        {"email": "player@example.test"},
        {"name": 7},
        {"name": "Ace"},
        {"name": "Ace#12"},
    ],
)
def test_contract_violations_are_invalid(server: FakeServer, overrides: dict) -> None:
    invalid(server.client(), sign(access_claims(**overrides)))


def test_clock_tolerance(server: FakeServer) -> None:
    token = sign(access_claims(exp=NOW, iat=NOW - 300))
    invalid(server.client(), token)
    assert server.client(clock_tolerance=5).validate_access_token(token)
    early = sign(access_claims(nbf=NOW + 5))
    assert server.client(clock_tolerance=5).validate_access_token(early)


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none"},
        {"alg": "HS256"},
        {"alg": "RS512"},
        {"jku": "https://evil.example.test/jwks"},
        {"x5u": "https://evil.example.test/cert"},
        {"jwk": {"kty": "RSA"}},
        {"crit": ["exp"]},
        {"kid": ""},
        {"kid": 7},
    ],
)
def test_unsafe_headers_are_invalid(server: FakeServer, header: dict) -> None:
    invalid(server.client(), sign(access_claims(), header=header))


@pytest.mark.parametrize("typ", [None, "JWT", "jwt", "id+jwt"])
def test_access_tokens_need_at_jwt_type(server: FakeServer, typ: object) -> None:
    invalid(server.client(), sign(access_claims(), typ=typ))  # type: ignore[arg-type]


def test_typ_is_case_insensitive(server: FakeServer) -> None:
    assert server.client().validate_access_token(sign(access_claims(), typ="application/AT+JWT"))


def test_signature_must_match(server: FakeServer) -> None:
    client = server.client()
    invalid(client, sign(access_claims(), key=fresh_key()))
    head, payload, signature = sign(access_claims()).split(".")
    tampered = b64url(json.dumps(access_claims(sub="usr_player0000000002")).encode())
    invalid(client, f"{head}.{tampered}.{signature}")
    invalid(client, f"{head}.{payload}.")
    invalid(client, f"{head}.{payload}.{signature[:-4]}")


@pytest.mark.parametrize(
    "token",
    ["", "a.b", "a.b.c.d", "!!!.e30.sig", "e30.e30.c2ln", "x" * 16_385, "e30=.e30.c2ln"],
)
def test_malformed_tokens_are_invalid(server: FakeServer, token: str) -> None:
    invalid(server.client(), token)


def test_duplicate_or_non_json_claims_are_invalid(server: FakeServer) -> None:
    claims = json.dumps(access_claims())
    duplicate = claims[:-1] + ', "sub": "usr_player0000000002"}'
    invalid(server.client(), sign({}, raw_payload=duplicate.encode()))
    nan = claims[:-1] + ', "nbf": NaN}'
    invalid(server.client(), sign({}, raw_payload=nan.encode()))
    invalid(server.client(), sign({}, raw_payload=b"[]"))


def test_configuration_is_checked(server: FakeServer) -> None:
    good = {"tenant_id": TENANT_ID, "issuer": ISSUER, "audience": AUDIENCE}
    bad = [
        {"tenant_id": "ten_short"},
        {"issuer": ISSUER + "/"},
        {"issuer": ISSUER.upper()},
        {"issuer": ISSUER.replace("https", "http")},
        {"issuer": f"https://auth.example.test/t/{OTHER_TENANT_ID}"},
        {"issuer": f"https://user@auth.example.test/t/{TENANT_ID}"},
        {"issuer": f"https://auth.example.test:443/t/{TENANT_ID}"},
        {"issuer": f"{ISSUER}?x=1"},
        {"issuer": None, "auth_origin": None},
        {"issuer": None, "auth_origin": "https://auth.example.test/path"},
        {"audience": ""},
        {"audience": "urn:auth4:management"},
        {"jwks_cache_ttl": 5},
        {"jwks_refresh_cooldown": 0},
        {"jwks_fetch_timeout": 11},
        {"clock_tolerance": 61},
        {"clock_tolerance": 1.5},
    ]
    for override in bad:
        with pytest.raises(ValueError):
            Auth4ServerClient(**{**good, **override}, transport=server)
    assert Auth4ServerClient(**good).jwks_url == f"{ISSUER}/.well-known/jwks.json"


def test_issuer_from_auth_origin() -> None:
    assert issuer_for("https://auth.example.test", TENANT_ID) == ISSUER
    assert issuer_for("https://auth.example.test/", TENANT_ID) == ISSUER
    assert issuer_for("http://localhost:8787", TENANT_ID) == f"http://localhost:8787/t/{TENANT_ID}"
    client = Auth4ServerClient(
        tenant_id=TENANT_ID, auth_origin="https://auth.example.test", audience=AUDIENCE
    )
    assert client.issuer == ISSUER
    for origin in (
        "http://auth.example.test",
        "https://a:b@auth.example.test",
        "ftp://auth.example.test",
    ):
        with pytest.raises(ValueError):
            issuer_for(origin, TENANT_ID)


def test_loopback_http_issuers_are_allowed() -> None:
    for origin in ("http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787"):
        issuer = f"{origin}/t/{TENANT_ID}"
        assert (
            Auth4ServerClient(tenant_id=TENANT_ID, issuer=issuer, audience=AUDIENCE).issuer
            == issuer
        )


def test_reprs_hold_no_tokens(server: FakeServer) -> None:
    token = server.client().validate_access_token(sign(access_claims()))
    assert "eyJ" not in repr(token)
    assert repr(server.client()).startswith("Auth4ServerClient(")
