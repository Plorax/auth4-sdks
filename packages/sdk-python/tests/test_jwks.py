from __future__ import annotations

import threading
import time

import pytest

from auth4 import Auth4TokenError, HttpRequest, HttpResponse
from conftest import JWKS_URL, FakeServer, access_claims, fresh_key, private_key, public_jwk, sign


def code_of(callable_) -> str:
    with pytest.raises(Auth4TokenError) as caught:
        callable_()
    return caught.value.code


def test_keys_are_cached(server: FakeServer) -> None:
    client = server.client()
    for _ in range(5):
        client.validate_access_token(sign(access_claims()))
    assert server.count(JWKS_URL) == 1
    assert server.requests[0].method == "GET"


def test_cache_expires_after_ttl(server: FakeServer) -> None:
    client = server.client(jwks_cache_ttl=60)
    client.validate_access_token(sign(access_claims()))
    server.advance(61)
    client.validate_access_token(
        sign(access_claims(iat=int(server.clock[0]), exp=int(server.clock[0]) + 300))
    )
    assert server.count(JWKS_URL) == 2


def test_rotation_refreshes_on_unknown_kid(server: FakeServer) -> None:
    client = server.client()
    client.validate_access_token(sign(access_claims()))
    rotated = fresh_key()
    server.jwks = {"keys": [public_jwk(private_key(), "key-1"), public_jwk(rotated, "key-2")]}
    token = sign(access_claims(), key=rotated, kid="key-2")
    assert client.validate_access_token(token).subject == "usr_player0000000001"
    assert server.count(JWKS_URL) == 2


def test_unknown_kid_refresh_is_rate_limited(server: FakeServer) -> None:
    client = server.client(jwks_refresh_cooldown=30)
    client.validate_access_token(sign(access_claims()))
    unknown = sign(access_claims(), kid="key-9")
    assert code_of(lambda: client.validate_access_token(unknown)) == "invalid_token"
    assert code_of(lambda: client.validate_access_token(unknown)) == "jwks_refresh_limited"
    assert server.count(JWKS_URL) == 2
    server.advance(31)
    assert code_of(lambda: client.validate_access_token(unknown)) == "invalid_token"
    assert server.count(JWKS_URL) == 3


def test_unavailable_jwks_is_an_outage(server: FakeServer) -> None:
    server.jwks_status = 503
    client = server.client()
    with pytest.raises(Auth4TokenError) as caught:
        client.validate_access_token(sign(access_claims()))
    assert caught.value.code == "jwks_unavailable" and caught.value.is_outage
    # Failed fetches are also rate limited, so an outage doesn't become a request flood.
    assert (
        code_of(lambda: client.validate_access_token(sign(access_claims())))
        == "jwks_refresh_limited"
    )
    server.jwks_status = 200
    server.advance(31)
    assert client.validate_access_token(sign(access_claims()))


@pytest.mark.parametrize(
    "jwks",
    [
        {"keys": []},
        {"keys": "nope"},
        {},
        {"keys": [public_jwk(private_key(), "key-1", alg="RS512")]},
        {"keys": [public_jwk(private_key(), "key-1", use="enc")]},
        {"keys": [public_jwk(private_key(), "key-1", key_ops=["sign"])]},
        {"keys": [{**public_jwk(private_key(), "key-1"), "d": "secret"}]},
        {"keys": [public_jwk(private_key(), "key-1"), public_jwk(private_key(), "key-1")]},
        {"keys": [public_jwk(private_key(), f"k{i}") for i in range(65)]},
        {"keys": [public_jwk(private_key(1024), "key-1")]},
    ],
)
def test_unusable_key_sets_are_refused(server: FakeServer, jwks: dict) -> None:
    server.jwks = jwks
    assert (
        code_of(lambda: server.client().validate_access_token(sign(access_claims())))
        == "jwks_unavailable"
    )


def test_unusable_keys_are_skipped(server: FakeServer) -> None:
    server.jwks = {"keys": [{"kty": "EC", "kid": "ec"}, public_jwk(private_key(), "key-1")]}
    assert server.client().validate_access_token(sign(access_claims()))


def test_oversized_response_is_refused(server: FakeServer) -> None:
    def huge(request: HttpRequest) -> HttpResponse:
        return HttpResponse(200, b" " * (256 * 1024 + 1))

    client = server.client(transport=huge)
    assert (
        code_of(lambda: client.validate_access_token(sign(access_claims()))) == "jwks_unavailable"
    )


def test_transport_errors_are_outages(server: FakeServer) -> None:
    def broken(request: HttpRequest) -> HttpResponse:
        raise TimeoutError("timed out")

    client = server.client(transport=broken)
    assert (
        code_of(lambda: client.validate_access_token(sign(access_claims()))) == "jwks_unavailable"
    )


def test_concurrent_requests_share_one_fetch(server: FakeServer) -> None:
    started = threading.Event()

    def slow() -> None:
        started.set()
        time.sleep(0.2)

    server.on_jwks = slow
    client = server.client()
    token = sign(access_claims())
    results: list = []

    def verify() -> None:
        results.append(client.validate_access_token(token).subject)

    threads = [threading.Thread(target=verify) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == ["usr_player0000000001"] * 8
    assert server.count(JWKS_URL) == 1
