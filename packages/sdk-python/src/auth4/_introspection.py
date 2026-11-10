"""Introspect mode (AUTH4D-155): after offline verification, asks the tenant's RFC 7662 endpoint
whether the token's session is still live. Unreachable or unexpected answers fail closed.
Mirrors @auth4/sdk-server's assertActive."""

from __future__ import annotations

import base64
import hashlib
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote, urlencode, urlsplit

from ._rules import CLIENT_ID, strict_json_object
from ._single_flight import SingleFlight
from .errors import Auth4TokenError
from .tokens import AccessToken
from .transport import USER_AGENT, HttpRequest, Transport, send_for_json

MAX_CACHE_ENTRIES = 10_000


@dataclass(frozen=True)
class IntrospectionOptions:
    """Confidential server client credentials and cache settings for introspect mode."""

    client_id: str
    """The server client's ID, ``cli_…``."""
    client_secret: str
    """Keep this in a secret store. The SDK never exposes, logs or serializes it."""
    cache_ttl: float = 5.0
    """Seconds an active answer is reused for the same token. Zero disables caching; at most 60."""
    timeout: float = 3.0
    """Seconds for one introspection request; 0.01 to 10."""

    def __repr__(self) -> str:
        # The secret is never part of the string form.
        return f"IntrospectionOptions(client_id={self.client_id!r})"


def bounded(name: str, value: float, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not (minimum <= value <= maximum)
    ):
        raise ValueError(f"{name} must be from {minimum} to {maximum} seconds.")
    return float(value)


def _form_encode(value: str) -> str:
    # Percent-encodes like encodeURIComponent; the server percent-decodes both parts.
    return quote(value, safe="!'()*~")


_Answer = tuple[bool | None, str | None, str | None, str | None, str | None]


class Introspector:
    def __init__(
        self,
        transport: Transport,
        issuer: str,
        tenant_id: str,
        options: IntrospectionOptions,
        now: Callable[[], float],
    ) -> None:
        if not isinstance(options.client_id, str) or not CLIENT_ID.match(options.client_id):
            raise ValueError("introspection.client_id must be a server client ID.")
        secret = options.client_secret
        if not isinstance(secret, str) or not 32 <= len(secret) <= 512:
            raise ValueError("introspection.client_secret must be the server client's secret.")
        self._cache_ttl = bounded("introspection.cache_ttl", options.cache_ttl, 0, 60)
        self._timeout = bounded("introspection.timeout", options.timeout, 0.01, 10)
        self._transport = transport
        self._tenant_id = tenant_id
        self._now = now
        # Like the JWKS URL, the endpoint comes only from the configured issuer, never from a token.
        origin = urlsplit(issuer)
        self.url = (
            f"{origin.scheme}://{origin.netloc}/oauth/introspect?"
            f"{urlencode({'tenant_id': tenant_id})}"
        )
        # RFC 6749 section 2.3.1: form-encode each part before Basic encoding.
        credentials = f"{_form_encode(options.client_id)}:{_form_encode(secret)}"
        self._authorization = "Basic " + base64.b64encode(credentials.encode("utf-8")).decode()
        self._gate = threading.Lock()
        self._cache: OrderedDict[str, tuple[bool, float]] = OrderedDict()
        self._flight: SingleFlight[_Answer] = SingleFlight()

    def __repr__(self) -> str:
        return f"Introspector(url={self.url!r})"

    @property
    def cache_size(self) -> int:
        with self._gate:
            return len(self._cache)

    def assert_active(self, token: str, claims: AccessToken) -> None:
        cache_key = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = self._now()
        with self._gate:
            cached = self._cache.get(cache_key)
            if cached is not None:
                active, expires_at = cached
                if expires_at > now:
                    if not active:
                        raise Auth4TokenError.invalid()
                    return
                del self._cache[cache_key]

        answer = self._flight.run(cache_key, lambda: self._introspect(token))
        active_value, subject, client_id, token_id, tenant_id = answer
        if active_value is None:
            raise Auth4TokenError(
                "introspection_unavailable", "The introspection response was not understood."
            )
        if active_value and (
            subject != claims.subject
            or client_id != claims.client_id
            or token_id != claims.token_id
            or tenant_id != self._tenant_id
        ):
            raise Auth4TokenError.invalid()
        # A revoked session never comes back, so an inactive answer is kept until the token expires.
        token_expires_at = float(claims.expires_at)
        expires_at = (
            min(now + self._cache_ttl, token_expires_at) if active_value else token_expires_at
        )
        if expires_at > now and (self._cache_ttl > 0 or not active_value):
            self._remember(cache_key, active_value, expires_at)
        if not active_value:
            raise Auth4TokenError.invalid()

    def _remember(self, key: str, active: bool, expires_at: float) -> None:
        with self._gate:
            if key not in self._cache and len(self._cache) >= MAX_CACHE_ENTRIES:
                self._cache.popitem(last=False)
            self._cache[key] = (active, expires_at)
            self._cache.move_to_end(key)

    def _introspect(self, token: str) -> _Answer:
        try:
            body = send_for_json(
                self._transport,
                HttpRequest(
                    method="POST",
                    url=self.url,
                    headers={
                        "Accept": "application/json",
                        "Authorization": self._authorization,
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": USER_AGENT,
                    },
                    body=urlencode({"token": token}).encode("ascii"),
                    timeout=self._timeout,
                ),
                "The introspection endpoint",
            )
            document = strict_json_object(body)
            if document is None:
                raise ValueError("Introspection returned a non-object body.")
        except Exception as cause:
            raise Auth4TokenError(
                "introspection_unavailable",
                "The token's session could not be checked with the configured issuer.",
            ) from cause

        def text(name: str) -> str | None:
            value = document.get(name)
            return value if isinstance(value, str) else None

        active = document.get("active")
        return (
            active if isinstance(active, bool) else None,
            text("sub"),
            text("client_id"),
            text("jti"),
            text("tenant_id"),
        )
