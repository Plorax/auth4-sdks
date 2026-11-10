"""Errors raised by the auth4.dev server SDK. Messages never contain tokens or secrets."""

from __future__ import annotations

from typing import Literal

TokenErrorCode = Literal[
    "invalid_token", "jwks_unavailable", "jwks_refresh_limited", "introspection_unavailable"
]


class Auth4TokenError(Exception):
    """Raised when verification fails. The codes match @auth4/sdk-server's error codes.

    Only ``invalid_token`` means the token itself is bad; the other codes are outages, which
    callers may report as 503.
    """

    def __init__(self, code: TokenErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: TokenErrorCode = code

    @property
    def is_outage(self) -> bool:
        """True for every code except ``invalid_token``."""
        return self.code != "invalid_token"

    @classmethod
    def invalid(cls) -> Auth4TokenError:
        return cls("invalid_token", "The token is invalid.")


class Auth4DiscoveryError(Exception):
    """Raised by :meth:`Auth4ServerClient.discover` when the issuer's metadata can't be used."""
