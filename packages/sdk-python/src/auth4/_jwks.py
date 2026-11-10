"""Signing keys from the configured issuer's JWKS, cached for ``jwks_cache_ttl``. An unknown
``kid`` triggers one refresh per cooldown, so key rotation needs no restart. Concurrent callers
share one in-flight fetch."""

from __future__ import annotations

import base64
import binascii
import math
import threading
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers

from ._rules import strict_json_object
from ._single_flight import SingleFlight
from .errors import Auth4TokenError
from .transport import USER_AGENT, HttpRequest, Transport, send_for_json

MAX_KEYS = 64
PRIVATE_RSA_PARAMETERS = ("d", "p", "q", "dp", "dq", "qi", "oth")


def b64url_decode(value: str) -> bytes | None:
    """Strict unpadded base64url. None for anything else."""
    if not isinstance(value, str) or "=" in value or not value.isascii():
        return None
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None


def _is_public_rs256_jwk(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    kid = value.get("kid")
    if (
        value.get("kty") != "RSA"
        or not isinstance(kid, str)
        or not 1 <= len(kid) <= 128
        or not isinstance(value.get("n"), str)
        or not isinstance(value.get("e"), str)
        or ("alg" in value and value["alg"] != "RS256")
        or ("use" in value and value["use"] != "sig")
    ):
        return False
    if "key_ops" in value and not (
        isinstance(value["key_ops"], list) and "verify" in value["key_ops"]
    ):
        return False
    return all(parameter not in value for parameter in PRIVATE_RSA_PARAMETERS)


def _import(jwk: dict[str, object]) -> RSAPublicKey:
    modulus = b64url_decode(jwk["n"])  # type: ignore[arg-type]
    exponent = b64url_decode(jwk["e"])  # type: ignore[arg-type]
    if not modulus or not exponent:
        raise ValueError("JWKS key is not valid base64url.")
    n = int.from_bytes(modulus, "big")
    # RS256 keys must be at least 2048 bits, as jose enforces for the TypeScript SDK.
    if n.bit_length() < 2048:
        raise ValueError("JWKS key is shorter than 2048 bits.")
    return RSAPublicNumbers(int.from_bytes(exponent, "big"), n).public_key()


@dataclass(frozen=True)
class _Snapshot:
    keys: dict[str, RSAPublicKey]
    expires_at: float


class JwksCache:
    def __init__(
        self,
        transport: Transport,
        jwks_url: str,
        cache_ttl: float,
        refresh_cooldown: float,
        fetch_timeout: float,
        now: Callable[[], float],
    ) -> None:
        self._transport = transport
        self._jwks_url = jwks_url
        self._cache_ttl = cache_ttl
        self._refresh_cooldown = refresh_cooldown
        self._fetch_timeout = fetch_timeout
        self._now = now
        self._gate = threading.Lock()
        self._flight: SingleFlight[None] = SingleFlight()
        self._cached: _Snapshot | None = None
        self._last_fetch_attempt_at = -math.inf
        self._last_unknown_kid_refresh_at = -math.inf

    def get_key(self, kid: str) -> RSAPublicKey | None:
        snapshot = self._cached
        if snapshot is not None and snapshot.expires_at > self._now():
            existing = snapshot.keys.get(kid)
            if existing is not None:
                return existing
            self._refresh(unknown_kid=True)
        else:
            self._refresh(unknown_kid=False)
        snapshot = self._cached
        return snapshot.keys.get(kid) if snapshot is not None else None

    def _refresh(self, unknown_kid: bool) -> None:
        def check_cooldown() -> None:
            now = self._now()
            if unknown_kid:
                if now - self._last_unknown_kid_refresh_at < self._refresh_cooldown:
                    raise _limited()
                self._last_unknown_kid_refresh_at = now
            elif now - self._last_fetch_attempt_at < self._refresh_cooldown:
                raise _limited()
            self._last_fetch_attempt_at = now

        self._flight.run("jwks", self._fetch, before_start=check_cooldown)

    def _fetch(self) -> None:
        try:
            body = send_for_json(
                self._transport,
                HttpRequest(
                    method="GET",
                    url=self._jwks_url,
                    headers={
                        "Accept": "application/jwk-set+json, application/json",
                        "User-Agent": USER_AGENT,
                    },
                    body=None,
                    timeout=self._fetch_timeout,
                ),
                "The JWKS endpoint",
            )
            document = strict_json_object(body)
            keys = document.get("keys") if document is not None else None
            if not isinstance(keys, list) or len(keys) > MAX_KEYS:
                raise ValueError("JWKS response has an invalid or oversized key set.")
            imported: dict[str, RSAPublicKey] = {}
            for candidate in keys:
                if not _is_public_rs256_jwk(candidate):
                    continue
                kid = candidate["kid"]
                if kid in imported:
                    raise ValueError("JWKS contains duplicate key IDs.")
                imported[kid] = _import(candidate)
            if not imported:
                raise ValueError("JWKS contains no usable RS256 public keys.")
        except Exception as cause:
            raise Auth4TokenError(
                "jwks_unavailable",
                "Signing keys could not be refreshed from the configured issuer.",
            ) from cause
        with self._gate:
            self._cached = _Snapshot(imported, self._now() + self._cache_ttl)


def _limited() -> Auth4TokenError:
    return Auth4TokenError("jwks_refresh_limited", "A signing-key refresh was recently attempted.")
