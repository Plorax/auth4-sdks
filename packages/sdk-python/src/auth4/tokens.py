"""Verified token types. Every value has already been checked when one of these exists."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Union

# A Union, not |, because this alias is evaluated at runtime on Python 3.10.
MetadataValue = Union[str, int, float, bool, None]  # noqa: UP007


@dataclass(frozen=True)
class AccessToken:
    """Claims from a verified access token. Tokens are never part of the repr."""

    subject: str
    """``sub``: the player's user ID. It stays the same when a guest upgrades."""
    tenant_id: str
    """``tenant_id``: always the configured project ID."""
    issuer: str
    """``iss``: always the configured issuer."""
    audience: str
    """``aud``: always the configured audience."""
    client_id: str
    """``client_id``: the application the token was issued to."""
    scope: str
    """``scope``: space-separated granted scopes."""
    session_id: str | None
    """``sid``: the session ID, when the token belongs to a session."""
    token_id: str
    """``jti``: the token ID."""
    issued_at: int
    """``iat``, in epoch seconds."""
    expires_at: int
    """``exp``, in epoch seconds: at most five minutes after ``issued_at``."""
    not_before: int | None
    """``nbf``, when present."""
    is_guest: bool
    """True only when the signed ``auth4_guest`` claim is true (AUTH4D-64). The claim is
    re-evaluated on every issuance, so it becomes false on the first token issued after a guest
    upgrades. Tokens without the claim are not guests."""
    roles: tuple[str, ...]
    """The subject's roles in the token's application, from the signed ``auth4_roles`` claim
    (AUTH4D-154). Empty when the claim is absent."""
    metadata: Mapping[str, MetadataValue] = field(default_factory=lambda: MappingProxyType({}))
    """The signed ``auth4_meta`` claim: flat per-user metadata. Empty when the claim is absent."""

    @property
    def scopes(self) -> tuple[str, ...]:
        """``scope`` split into names."""
        return tuple(self.scope.split(" "))

    def has_role(self, role: str) -> bool:
        """True when the token carries ``role``. Exact and case-sensitive."""
        return role in self.roles

    def has_any_role(self, roles: Iterable[str]) -> bool:
        """True when the token carries at least one of ``roles``. An empty list never matches."""
        return any(role in self.roles for role in roles)

    def has_scope(self, scope: str) -> bool:
        """True when ``scope`` was granted. Exact and case-sensitive."""
        return scope in self.scopes


@dataclass(frozen=True)
class IdToken:
    """Claims from a verified ID token. ID tokens prove a sign-in to the application that
    requested it; they never authorize API calls, so they have their own type and validation."""

    subject: str
    tenant_id: str
    issuer: str
    client_id: str
    """``aud``: the client ID the ID token was issued to."""
    token_id: str
    issued_at: int
    expires_at: int
    auth_time: int
    nonce: str | None
    """``nonce``, when the authorization request sent one."""
    email: str | None
    """``email``, when the ``email`` scope was granted."""
    email_verified: bool | None


@dataclass(frozen=True)
class Discovery:
    """The checked parts of a tenant's OpenID Connect discovery document."""

    issuer: str
    jwks_uri: str
    token_endpoint: str | None
    userinfo_endpoint: str | None
    introspection_endpoint: str | None


def has_role(token: AccessToken, role: str) -> bool:
    """Module-level form of :meth:`AccessToken.has_role`, matching @auth4/sdk-server's hasRole."""
    return token.has_role(role)


def has_any_role(token: AccessToken, roles: Iterable[str]) -> bool:
    """Module-level form of :meth:`AccessToken.has_any_role`."""
    return token.has_any_role(roles)
