"""Verifies auth4.dev access tokens for one tenant and resource audience, like
``Auth4ServerClient`` in @auth4/sdk-server."""

from __future__ import annotations

import hmac
import re
import time
from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from . import _rules as rules
from ._introspection import IntrospectionOptions, Introspector, bounded
from ._jwks import JwksCache, b64url_decode
from .errors import Auth4DiscoveryError, Auth4TokenError
from .tokens import AccessToken, Discovery, IdToken
from .transport import USER_AGENT, HttpRequest, Transport, send_for_json, urllib_transport

_BEARER = re.compile(r"^Bearer ([^\s,]+)\Z", re.IGNORECASE)
_ACCESS_TYPES = ("at+jwt", "application/at+jwt")


def parse_bearer_token(header: str | None) -> str | None:
    """Parses a single RFC 6750 Bearer credential. It does not validate the token."""
    if not isinstance(header, str) or len(header) > rules.MAX_TOKEN_LENGTH + 16:
        return None
    match = _BEARER.match(header)
    return match.group(1) if match else None


def issuer_for(auth_origin: str, tenant_id: str) -> str:
    """The issuer for a project on an auth origin, for example ``https://auth.auth4.dev/t/ten_…``."""
    if not isinstance(tenant_id, str) or not rules.TENANT_ID.match(tenant_id):
        raise ValueError("tenant_id must be a project ID (ten_…).")
    return rules.issuer_from_origin(tenant_id, auth_origin)


class Auth4ServerClient:
    """Verifies access tokens for one configured tenant and resource audience.

    Signing keys are fetched only from the URL derived from the configured issuer. Create one
    instance per audience and reuse it, so its key cache is shared across requests. Thread-safe.
    Construction makes no network calls.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        audience: str,
        issuer: str | None = None,
        auth_origin: str | None = None,
        transport: Transport | None = None,
        jwks_cache_ttl: float = 300.0,
        jwks_refresh_cooldown: float = 30.0,
        jwks_fetch_timeout: float = 3.0,
        clock_tolerance: int = 0,
        now: Callable[[], float] | None = None,
        introspection: IntrospectionOptions | None = None,
    ) -> None:
        """
        :param tenant_id: The project ID, ``ten_…``.
        :param audience: The API audience this server accepts: the client ID of the application
            calling it.
        :param issuer: The trusted, configured issuer ``{AUTH_ORIGIN}/t/{tenant_id}``. Leave it out
            and pass ``auth_origin`` to have it derived.
        :param transport: Injectable for tests and custom HTTP stacks.
        :param jwks_cache_ttl: Seconds a fetched key set is trusted; 10 to 3600.
        :param jwks_refresh_cooldown: Minimum seconds between key refreshes; 1 to 600.
        :param jwks_fetch_timeout: Seconds for one key-set request; 0.01 to 10.
        :param clock_tolerance: Whole seconds of allowed drift for ``exp`` and ``nbf``; 0 to 60.
        :param now: Injectable epoch clock in seconds, primarily for deterministic tests.
        :param introspection: AUTH4D-155: opt in to a live revocation check. After local
            verification succeeds, the token is also sent to the tenant's introspection endpoint,
            so a revoked session is refused within ``cache_ttl`` instead of up to five minutes
            later. Off by default.
        """
        if not isinstance(tenant_id, str) or not rules.TENANT_ID.match(tenant_id):
            raise ValueError("tenant_id must be a project ID (ten_…).")
        self.tenant_id = tenant_id
        if issuer:
            self.issuer = rules.validate_issuer(tenant_id, issuer)
        elif auth_origin:
            self.issuer = rules.issuer_from_origin(tenant_id, auth_origin)
        else:
            raise ValueError("Pass issuer or auth_origin.")
        if not isinstance(audience, str) or not 1 <= len(audience) <= 255:
            raise ValueError("audience must be 1 to 255 characters.")
        if audience == rules.MANAGEMENT_AUDIENCE:
            raise ValueError("Customer server clients cannot use the management audience.")
        self.audience = audience
        # No token-supplied issuer, jku or x5u value is ever used to build this URL.
        self.jwks_url = f"{self.issuer}/.well-known/jwks.json"

        cache_ttl = bounded("jwks_cache_ttl", jwks_cache_ttl, 10, 3600)
        cooldown = bounded("jwks_refresh_cooldown", jwks_refresh_cooldown, 1, 600)
        self._fetch_timeout = bounded("jwks_fetch_timeout", jwks_fetch_timeout, 0.01, 10)
        if not rules.is_int(clock_tolerance) or not 0 <= clock_tolerance <= 60:
            raise ValueError("clock_tolerance must be whole seconds from 0 to 60.")
        self._clock_tolerance = clock_tolerance
        self._now = now or time.time
        self._transport = transport or urllib_transport
        self._jwks = JwksCache(
            self._transport, self.jwks_url, cache_ttl, cooldown, self._fetch_timeout, self._now
        )
        self._introspector = (
            Introspector(self._transport, self.issuer, tenant_id, introspection, self._now)
            if introspection is not None
            else None
        )

    @property
    def introspection_url(self) -> str | None:
        """The endpoint introspect mode calls, derived from the configured issuer; None when off."""
        return self._introspector.url if self._introspector else None

    def __repr__(self) -> str:
        return (
            f"Auth4ServerClient(issuer={self.issuer!r}, audience={self.audience!r}, "
            f"introspection={self._introspector is not None})"
        )

    def discover(self) -> Discovery:
        """Fetches ``{issuer}/.well-known/openid-configuration`` and checks that it names the
        configured issuer, the derived JWKS URL and RS256. Optional: verification never depends on
        it, so call it at startup to catch a misconfigured project or origin early."""
        try:
            body = send_for_json(
                self._transport,
                HttpRequest(
                    method="GET",
                    url=f"{self.issuer}/.well-known/openid-configuration",
                    headers={"Accept": "application/json", "User-Agent": USER_AGENT},
                    body=None,
                    timeout=self._fetch_timeout,
                ),
                "The discovery endpoint",
            )
        except Exception as cause:
            raise Auth4DiscoveryError(
                "The issuer's discovery document could not be fetched."
            ) from cause
        document = rules.strict_json_object(body)
        if document is None:
            raise Auth4DiscoveryError("The issuer's discovery document could not be fetched.")

        def text(name: str) -> str | None:
            value = document.get(name)
            return value if isinstance(value, str) else None

        if text("issuer") != self.issuer:
            raise Auth4DiscoveryError("The discovery document names a different issuer.")
        if text("jwks_uri") != self.jwks_url:
            raise Auth4DiscoveryError("The discovery document names a different JWKS URL.")
        algs = document.get("id_token_signing_alg_values_supported")
        if not isinstance(algs, list) or "RS256" not in algs:
            raise Auth4DiscoveryError("The issuer does not advertise RS256.")
        introspection = text("introspection_endpoint")
        if self.introspection_url is not None and introspection != self.introspection_url:
            raise Auth4DiscoveryError(
                "The issuer does not advertise the introspection endpoint introspect mode uses."
            )
        return Discovery(
            issuer=self.issuer,
            jwks_uri=self.jwks_url,
            token_endpoint=text("token_endpoint"),
            userinfo_endpoint=text("userinfo_endpoint"),
            introspection_endpoint=introspection,
        )

    def validate_access_token(self, token: str) -> AccessToken:
        """Verifies an access token: RS256 signature from the issuer's keys, ``typ`` at+jwt,
        ``iss``, ``aud``, ``exp``, ``nbf``, ``tenant_id`` and the claim contract. Raises
        :class:`Auth4TokenError`; in introspect mode it also checks the session."""
        payload = self._verify_signature(token, expected_type="access")
        verified = self._read_access_claims(payload)
        if verified is None:
            raise Auth4TokenError.invalid()
        if self._introspector is not None:
            self._introspector.assert_active(token, verified)
        return verified

    def validate_authorization_header(self, header: str | None) -> AccessToken:
        """Verifies an Authorization header value and rejects absent or malformed Bearer
        credentials."""
        token = parse_bearer_token(header)
        if token is None:
            raise Auth4TokenError.invalid()
        return self.validate_access_token(token)

    def validate_id_token(
        self, id_token: str, client_id: str, expected_nonce: str | None = None
    ) -> IdToken:
        """Verifies an ID token for ``client_id``. ID tokens have ``typ`` JWT and ``token_use`` id,
        so neither validation path accepts the other kind of token. Pass the ``expected_nonce``
        your authorization request sent, if any. Never use an ID token to authorize an API call."""
        if not isinstance(client_id, str) or not rules.CLIENT_ID.match(client_id):
            raise ValueError("client_id must be an application client ID (cli_…).")
        payload = self._verify_signature(id_token, expected_type="id")
        verified = self._read_id_claims(payload, client_id)
        if verified is None:
            raise Auth4TokenError.invalid()
        if expected_nonce is not None and (
            verified.nonce is None
            or not hmac.compare_digest(verified.nonce.encode(), expected_nonce.encode())
        ):
            raise Auth4TokenError.invalid()
        return verified

    def _verify_signature(self, token: str, expected_type: str) -> Mapping[str, Any]:
        if not isinstance(token, str) or not 0 < len(token) <= rules.MAX_TOKEN_LENGTH:
            raise Auth4TokenError.invalid()
        parts = token.split(".")
        if len(parts) != 3:
            raise Auth4TokenError.invalid()
        header_bytes, payload_bytes, signature = (b64url_decode(part) for part in parts)
        if header_bytes is None or payload_bytes is None or not signature:
            raise Auth4TokenError.invalid()
        header = rules.strict_json_object(header_bytes)
        if header is None:
            raise Auth4TokenError.invalid()

        # typ separates the two token kinds, as packages/crypto signs them.
        typ = header.get("typ")
        typ = typ.lower() if isinstance(typ, str) else None
        type_matches = typ in _ACCESS_TYPES if expected_type == "access" else typ == "jwt"
        kid = header.get("kid")
        if (
            header.get("alg") != "RS256"
            or not type_matches
            or not isinstance(kid, str)
            or not 1 <= len(kid) <= 128
            or any(name in header for name in ("jku", "x5u", "jwk", "crit"))
        ):
            raise Auth4TokenError.invalid()

        key = self._jwks.get_key(kid)
        if key is None:
            raise Auth4TokenError.invalid()
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        try:
            key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except (InvalidSignature, ValueError):
            raise Auth4TokenError.invalid() from None
        payload = rules.strict_json_object(payload_bytes)
        if payload is None:
            raise Auth4TokenError.invalid()
        return payload

    def _read_common(
        self, payload: Mapping[str, Any], allowed: frozenset[str], token_use: str, max_lifetime: int
    ) -> tuple[str, str, int, int, int | None] | None:
        """Registered claims shared by both token kinds; None on any violation."""
        # Unknown claims fail, like the strict contract schemas. Duplicates already failed parsing.
        if any(name not in allowed for name in payload):
            return None
        sub, jti = payload.get("sub"), payload.get("jti")
        exp, iat = _positive_int(payload.get("exp")), _positive_int(payload.get("iat"))
        nbf = _positive_int(payload.get("nbf"))
        if (
            payload.get("iss") != self.issuer
            or not isinstance(sub, str)
            or not rules.USER_ID.match(sub)
            or not isinstance(jti, str)
            or not rules.TOKEN_ID.match(jti)
            or payload.get("tenant_id") != self.tenant_id
            or payload.get("token_use") != token_use
            or exp is None
            or iat is None
            or ("nbf" in payload and nbf is None)
        ):
            return None
        if exp <= iat or exp - iat > max_lifetime:
            return None
        # Same comparisons as jose: whole seconds, with the configured tolerance.
        now = int(self._now())
        if exp <= now - self._clock_tolerance:
            return None
        if nbf is not None and nbf > now + self._clock_tolerance:
            return None
        return sub, jti, exp, iat, nbf

    def _read_access_claims(self, payload: Mapping[str, Any]) -> AccessToken | None:
        common = self._read_common(
            payload, rules.ACCESS_TOKEN_CLAIMS, "access", rules.ACCESS_TOKEN_LIFETIME_SECONDS
        )
        if common is None:
            return None
        sub, jti, exp, iat, nbf = common
        # aud is a single string in the contract; an array is refused.
        aud, client_id, scope = payload.get("aud"), payload.get("client_id"), payload.get("scope")
        if (
            aud != self.audience
            or aud == rules.MANAGEMENT_AUDIENCE
            or not isinstance(client_id, str)
            or not rules.CLIENT_ID.match(client_id)
            or not isinstance(scope, str)
            or not rules.is_scope_list(scope)
        ):
            return None
        sid = payload.get("sid")
        if "sid" in payload and not (isinstance(sid, str) and rules.SESSION_ID.match(sid)):
            return None
        # A non-boolean auth4_guest and malformed auth4_roles or auth4_meta make the token
        # invalid; absent claims mean not a guest, no roles and no metadata.
        guest = payload.get(rules.GUEST_CLAIM, False)
        roles = rules.read_roles(payload[rules.ROLES_CLAIM]) if rules.ROLES_CLAIM in payload else ()
        metadata = (
            rules.read_metadata(payload[rules.METADATA_CLAIM])
            if rules.METADATA_CLAIM in payload
            else {}
        )
        if not isinstance(guest, bool) or roles is None or metadata is None:
            return None
        if not rules.is_idp(payload) or not rules.is_player_name(payload):
            return None
        return AccessToken(
            subject=sub,
            tenant_id=self.tenant_id,
            issuer=self.issuer,
            audience=aud,
            client_id=client_id,
            scope=scope,
            session_id=sid,
            token_id=jti,
            issued_at=iat,
            expires_at=exp,
            not_before=nbf,
            is_guest=guest,
            roles=roles,
            metadata=MappingProxyType(metadata),
        )

    def _read_id_claims(self, payload: Mapping[str, Any], client_id: str) -> IdToken | None:
        common = self._read_common(
            payload, rules.ID_TOKEN_CLAIMS, "id", rules.ID_TOKEN_LIFETIME_SECONDS
        )
        if common is None:
            return None
        sub, jti, exp, iat, _ = common
        auth_time = _positive_int(payload.get("auth_time"))
        if payload.get("aud") != client_id or auth_time is None:
            return None
        nonce = payload.get("nonce")
        if "nonce" in payload and not (
            isinstance(nonce, str) and 16 <= rules.js_length(nonce) <= 512
        ):
            return None
        email = payload.get("email")
        if "email" in payload and not (isinstance(email, str) and rules.is_email_address(email)):
            return None
        email_verified = payload.get("email_verified")
        if "email_verified" in payload and not isinstance(email_verified, bool):
            return None
        if email_verified is True and email is None:
            return None
        if not rules.is_idp(payload):
            return None
        return IdToken(
            subject=sub,
            tenant_id=self.tenant_id,
            issuer=self.issuer,
            client_id=client_id,
            token_id=jti,
            issued_at=iat,
            expires_at=exp,
            auth_time=auth_time,
            nonce=nonce,
            email=email,
            email_verified=email_verified,
        )


def _positive_int(value: object) -> int | None:
    """The value when it is a positive JSON integer; None otherwise, including for true and 1.0."""
    return value if type(value) is int and value > 0 else None
