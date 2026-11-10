"""Wire rules copied from packages/contracts (AccessTokenClaimsSchema, IdTokenClaimsSchema and
custom-claims.ts). tests/integration/auth4d-171.python-sdk.test.ts keeps them in step.

Patterns end in \\Z because Python's $ also matches before a trailing newline.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

MANAGEMENT_AUDIENCE = "urn:auth4:management"
GUEST_CLAIM = "auth4_guest"
ROLES_CLAIM = "auth4_roles"
METADATA_CLAIM = "auth4_meta"
ACCESS_TOKEN_LIFETIME_SECONDS = 300
ID_TOKEN_LIFETIME_SECONDS = 300
MAX_TOKEN_LENGTH = 16_384
MAX_SCOPES = 32
MAX_ROLES_PER_TOKEN = 20
MAX_METADATA_KEYS = 32
MAX_METADATA_BYTES = 2_048
MAX_METADATA_STRING_LENGTH = 256

TENANT_ID = re.compile(r"^ten_[A-Za-z0-9]{16,64}\Z")
CLIENT_ID = re.compile(r"^cli_[A-Za-z0-9]{16,64}\Z")
USER_ID = re.compile(r"^usr_[A-Za-z0-9]{16,64}\Z")
SESSION_ID = re.compile(r"^ses_[A-Za-z0-9]{16,64}\Z")
TOKEN_ID = re.compile(r"^jti_[A-Za-z0-9_-]{16,64}\Z")
SCOPE_NAME = re.compile(r"^[a-z][a-z0-9:_-]{0,63}\Z")
ROLE_NAME = re.compile(r"^[a-z][a-z0-9_.-]{0,63}\Z")
METADATA_KEY = re.compile(r"^[a-z][a-z0-9_]{0,39}\Z")
IDP = re.compile(r"^[a-z][a-z0-9_]{1,31}\Z")
# AUTH4D-324: the opt-in player name claim, Name#1234 (read leniently).
PLAYER_NAME = re.compile(r"^[^#]{1,64}#[0-9]{4}\Z")

RESERVED_CLAIM_NAMES = (
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "azp",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "sid",
    "scope",
    "client_id",
    "tenant_id",
    "token_use",
    "email",
    "email_verified",
)

# The contract schemas are strict: any other claim makes the token invalid.
ACCESS_TOKEN_CLAIMS = frozenset(
    {
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "tenant_id",
        "token_use",
        "client_id",
        "scope",
        "sid",
        GUEST_CLAIM,
        ROLES_CLAIM,
        METADATA_CLAIM,
        "idp",
        "name",
    }
)

ID_TOKEN_CLAIMS = frozenset(
    {
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "tenant_id",
        "token_use",
        "auth_time",
        "nonce",
        "email",
        "email_verified",
        "idp",
    }
)

_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def is_idp(payload: Mapping[str, Any]) -> bool:
    """AUTH4D-258: idp, when present, is any well-formed method name."""
    idp = payload.get("idp")
    return "idp" not in payload or (isinstance(idp, str) and IDP.match(idp) is not None)


def is_player_name(payload: Mapping[str, Any]) -> bool:
    """AUTH4D-324: name, when present, is Name#1234."""
    name = payload.get("name")
    return "name" not in payload or (isinstance(name, str) and PLAYER_NAME.match(name) is not None)


def is_reserved_claim_name(name: str) -> bool:
    return name in RESERVED_CLAIM_NAMES or name.startswith("auth4_")


def js_length(value: str) -> int:
    """String length in UTF-16 code units, as zod's .max() counts it."""
    return len(value.encode("utf-16-le")) // 2


def is_int(value: object) -> bool:
    # bool is a subclass of int; JSON true must not pass as a number.
    return type(value) is int


def is_scope_list(value: str) -> bool:
    if not 1 <= js_length(value) <= 2_048:
        return False
    scopes = value.split(" ")
    return (
        len(scopes) <= MAX_SCOPES
        and all(SCOPE_NAME.match(scope) for scope in scopes)
        and len(set(scopes)) == len(scopes)
    )


def read_roles(value: object) -> tuple[str, ...] | None:
    """RolesClaimSchema: 1 to 20 unique role names."""
    if not isinstance(value, list):
        return None
    roles: list[str] = []
    for item in value:
        if not isinstance(item, str) or not ROLE_NAME.match(item) or item in roles:
            return None
        roles.append(item)
    return tuple(roles) if 1 <= len(roles) <= MAX_ROLES_PER_TOKEN else None


def read_metadata(value: object) -> dict[str, Any] | None:
    """MetadataClaimSchema: a non-empty flat object of scalar values, at most 2048 bytes."""
    if not isinstance(value, dict):
        return None
    # The same measure as metadataByteLength: UTF-8 bytes of the compact JSON.
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_METADATA_BYTES:
        return None
    metadata: dict[str, Any] = {}
    for key, item in value.items():
        if not METADATA_KEY.match(key) or is_reserved_claim_name(key):
            return None
        if isinstance(item, str):
            if js_length(item) > MAX_METADATA_STRING_LENGTH:
                return None
        elif not (item is None or isinstance(item, (bool, int, float))):
            return None
        metadata[key] = item
    return metadata if 1 <= len(metadata) <= MAX_METADATA_KEYS else None


def is_email_address(value: str) -> bool:
    at = value.find("@")
    return (
        js_length(value) <= 254
        and at > 0
        and at == value.rfind("@")
        and at < len(value) - 1
        and not any(char.isspace() for char in value)
    )


def _canonical_origin(url: str, name: str) -> str:
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as cause:
        raise ValueError(f"{name} must be a valid absolute URL.") from cause
    host = parts.hostname or ""
    scheme = parts.scheme.lower()
    loopback = host in _LOOPBACK_HOSTS
    secure = scheme == "https" or (scheme == "http" and loopback)
    if not host or not host.isascii() or not secure or parts.username is not None:
        raise ValueError(f"{name} must use https (http only on loopback) and no credentials.")
    netloc = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    if port is not None and port != default_port:
        netloc = f"{netloc}:{port}"
    return f"{scheme}://{netloc}"


def validate_issuer(tenant_id: str, issuer: str) -> str:
    """Mirrors @auth4/sdk-server validateIssuer: https (or http on loopback), no credentials,
    query or fragment, path exactly /t/{tenantId}, already in canonical form."""
    if not isinstance(issuer, str):
        raise ValueError("issuer must be a valid absolute URL.")
    canonical = f"{_canonical_origin(issuer, 'issuer')}/t/{tenant_id}"
    if issuer != canonical:
        raise ValueError("issuer must be the canonical issuer URL for tenant_id.")
    return issuer


def issuer_from_origin(tenant_id: str, auth_origin: str) -> str:
    if not isinstance(auth_origin, str):
        raise ValueError("auth_origin must be an origin such as https://auth.auth4.dev.")
    parts = urlsplit(auth_origin)
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("auth_origin must be an origin such as https://auth.auth4.dev.")
    return f"{_canonical_origin(auth_origin, 'auth_origin')}/t/{tenant_id}"


def strict_json_object(raw: bytes) -> Mapping[str, Any] | None:
    """Parses a JSON object, refusing duplicate names, NaN and Infinity. None on any violation."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate member")
            result[key] = value
        return result

    def constant(name: str) -> Any:
        raise ValueError(f"{name} is not JSON")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return value if isinstance(value, dict) else None
