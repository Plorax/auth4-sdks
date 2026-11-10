"""Local fixtures: RSA keys generated in memory, tokens signed here, and a fake transport that
serves JWKS, discovery and introspection. Nothing calls a live endpoint."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from auth4 import Auth4ServerClient, HttpRequest, HttpResponse

TENANT_ID = "ten_abcdefghijklmnop"
OTHER_TENANT_ID = "ten_qrstuvwxyzabcdef"
ISSUER = f"https://auth.example.test/t/{TENANT_ID}"
AUDIENCE = "cli_gameclient000001"
SERVER_CLIENT_ID = "cli_serverclient00001"
SERVER_CLIENT_SECRET = "s" * 40
NOW = 1_800_000_000
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
INTROSPECTION_URL = f"https://auth.example.test/oauth/introspect?tenant_id={TENANT_ID}"

_KEYS: dict[int, rsa.RSAPrivateKey] = {}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def private_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    # Key generation is slow, so keep one key per size for the session.
    if bits not in _KEYS:
        _KEYS[bits] = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return _KEYS[bits]


def fresh_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def public_jwk(key: rsa.RSAPrivateKey, kid: str, **extra: Any) -> dict[str, Any]:
    numbers = key.public_key().public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": b64url(n),
        "e": b64url(e),
        **extra,
    }


def sign(
    claims: dict[str, Any],
    *,
    key: rsa.RSAPrivateKey | None = None,
    kid: str = "key-1",
    typ: str | None = "at+jwt",
    header: dict[str, Any] | None = None,
    raw_payload: bytes | None = None,
) -> str:
    head: dict[str, Any] = {"alg": "RS256", "kid": kid}
    if typ is not None:
        head["typ"] = typ
    head.update(header or {})
    payload = raw_payload if raw_payload is not None else json.dumps(claims).encode("utf-8")
    signing_input = f"{b64url(json.dumps(head).encode())}.{b64url(payload)}"
    signature = (key or private_key()).sign(
        signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )
    return f"{signing_input}.{b64url(signature)}"


def access_claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "usr_player0000000001",
        "aud": AUDIENCE,
        "exp": NOW + 300,
        "iat": NOW,
        "jti": "jti_token000000000001",
        "tenant_id": TENANT_ID,
        "token_use": "access",
        "client_id": AUDIENCE,
        "scope": "openid profile",
        "sid": "ses_session000000001",
    }
    claims.update(overrides)
    return {name: value for name, value in claims.items() if value is not _DROP}


def id_claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "usr_player0000000001",
        "aud": AUDIENCE,
        "exp": NOW + 300,
        "iat": NOW,
        "jti": "jti_token000000000002",
        "tenant_id": TENANT_ID,
        "token_use": "id",
        "auth_time": NOW - 10,
        "nonce": "nonce-0123456789abcdef",
        "email": "player@example.test",
        "email_verified": True,
    }
    claims.update(overrides)
    return {name: value for name, value in claims.items() if value is not _DROP}


_DROP = object()
DROP: Any = _DROP
"""Pass as a claim value to remove the claim."""


@dataclass
class FakeServer:
    """Routes requests by URL. Handlers return an HttpResponse or raise."""

    clock: list[float]
    jwks: dict[str, Any] = field(
        default_factory=lambda: {"keys": [public_jwk(private_key(), "key-1")]}
    )
    discovery: dict[str, Any] | None = None
    introspection: Callable[[HttpRequest], HttpResponse] = field(
        default=lambda request: HttpResponse(500, b"")
    )
    jwks_status: int = 200
    requests: list[HttpRequest] = field(default_factory=list)
    on_jwks: Callable[[], None] | None = None

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if request.url == JWKS_URL:
            if self.on_jwks is not None:
                self.on_jwks()
            return HttpResponse(self.jwks_status, json.dumps(self.jwks).encode())
        if request.url == DISCOVERY_URL and self.discovery is not None:
            return HttpResponse(200, json.dumps(self.discovery).encode())
        if request.url == INTROSPECTION_URL:
            return self.introspection(request)
        raise AssertionError(f"unexpected request to {request.url}")

    def count(self, url: str) -> int:
        return sum(1 for request in self.requests if request.url == url)

    def client(self, **options: Any) -> Auth4ServerClient:
        values: dict[str, Any] = {
            "tenant_id": TENANT_ID,
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "transport": self,
            "now": lambda: self.clock[0],
        }
        values.update(options)
        return Auth4ServerClient(**values)

    def advance(self, seconds: float) -> None:
        self.clock[0] += seconds


@pytest.fixture
def server() -> FakeServer:
    return FakeServer(clock=[float(NOW)])
