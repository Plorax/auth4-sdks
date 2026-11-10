"""FastAPI integration. Install with ``pip install "auth4[fastapi]"``.

``Auth4Bearer`` is a dependency that returns the verified :class:`~auth4.AccessToken`::

    auth4 = Auth4ServerClient(tenant_id=..., auth_origin=..., audience=...)
    player = Auth4Bearer(auth4)

    @app.get("/profile")
    def profile(token: AccessToken = Depends(player)): ...

Invalid or missing tokens get 401 with ``WWW-Authenticate: Bearer realm="auth4"``. Outages (keys or
introspection unavailable) get 503 with ``Retry-After: 5``, so players aren't signed out by them.
A valid token that lacks a required role or scope, or is a guest where guests aren't allowed,
gets 403.
"""

from __future__ import annotations

from collections.abc import Iterable

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .client import Auth4ServerClient
from .errors import Auth4TokenError
from .tokens import AccessToken

__all__ = ["Auth4Bearer"]

# Only documents the scheme in OpenAPI; the header is parsed and checked by the SDK.
_scheme = HTTPBearer(auto_error=False, scheme_name="auth4")

_CHALLENGE = {"WWW-Authenticate": 'Bearer realm="auth4"'}


class Auth4Bearer:
    """A FastAPI dependency that verifies the request's Bearer access token.

    :param any_role: When set, the token must carry at least one of these roles.
    :param allow_guests: Set False to refuse guest players, for example on trading endpoints.
    :param scopes: Scopes the token must all carry.
    """

    def __init__(
        self,
        client: Auth4ServerClient,
        *,
        any_role: Iterable[str] = (),
        allow_guests: bool = True,
        scopes: Iterable[str] = (),
    ) -> None:
        self.client = client
        self.any_role = tuple(any_role)
        self.allow_guests = allow_guests
        self.scopes = tuple(scopes)

    # A plain function, so FastAPI runs it in its threadpool; key fetches never block the loop.
    def __call__(
        self,
        request: Request,
        _credentials: HTTPAuthorizationCredentials | None = Security(_scheme),
    ) -> AccessToken:
        try:
            token = self.client.validate_authorization_header(request.headers.get("authorization"))
        except Auth4TokenError as error:
            if error.is_outage:
                raise HTTPException(503, "unavailable", headers={"Retry-After": "5"}) from None
            raise HTTPException(401, "unauthorized", headers=_CHALLENGE) from None
        if (
            (self.any_role and not token.has_any_role(self.any_role))
            or (token.is_guest and not self.allow_guests)
            or not all(token.has_scope(scope) for scope in self.scopes)
        ):
            raise HTTPException(403, "forbidden")
        request.state.auth4 = token
        return token
