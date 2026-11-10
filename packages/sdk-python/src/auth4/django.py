"""Django integration. Install with ``pip install "auth4[django]"``.

Configure one client in settings::

    AUTH4 = {
        "TENANT_ID": "ten_…",
        "AUTH_ORIGIN": "https://auth.auth4.dev",  # or "ISSUER": "https://auth.auth4.dev/t/ten_…"
        "AUDIENCE": "cli_…",
        # Optional introspect mode; read the secret from your secret store, never commit it.
        # "INTROSPECTION": {"CLIENT_ID": "cli_…", "CLIENT_SECRET": os.environ["…"]},
    }

and protect views with :func:`auth4_required`::

    @auth4_required()
    def profile(request):
        return JsonResponse({"player": request.auth4.subject})

Responses match the other server SDKs: 401 ``{"error": "unauthorized"}`` with
``WWW-Authenticate: Bearer realm="auth4"``, 503 ``{"error": "unavailable"}`` with
``Retry-After: 5`` for outages, and 403 ``{"error": "forbidden"}`` for a missing role or scope or
a refused guest.
"""

from __future__ import annotations

import functools
import threading
from collections.abc import Callable, Iterable
from inspect import iscoroutinefunction
from typing import Any, TypeVar, cast

from asgiref.sync import sync_to_async
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.http import HttpRequest, HttpResponse, JsonResponse

from ._introspection import IntrospectionOptions
from .client import Auth4ServerClient
from .errors import Auth4TokenError
from .tokens import AccessToken

__all__ = ["auth4_required", "authenticate", "get_client"]

View = TypeVar("View", bound=Callable[..., Any])

_lock = threading.Lock()
_client: Auth4ServerClient | None = None


def get_client() -> Auth4ServerClient:
    """The client built from ``settings.AUTH4``, created once and shared by every request."""
    global _client
    with _lock:
        if _client is None:
            config = getattr(settings, "AUTH4", None)
            if not isinstance(config, dict):
                raise ImproperlyConfigured("Set AUTH4 in your Django settings.")
            introspection = config.get("INTROSPECTION")
            try:
                _client = Auth4ServerClient(
                    tenant_id=config.get("TENANT_ID", ""),
                    audience=config.get("AUDIENCE", ""),
                    issuer=config.get("ISSUER"),
                    auth_origin=config.get("AUTH_ORIGIN"),
                    introspection=(
                        IntrospectionOptions(
                            client_id=introspection.get("CLIENT_ID", ""),
                            client_secret=introspection.get("CLIENT_SECRET", ""),
                            cache_ttl=introspection.get("CACHE_TTL", 5.0),
                        )
                        if introspection
                        else None
                    ),
                )
            except ValueError as error:
                raise ImproperlyConfigured(f"AUTH4: {error}") from None
        return _client


def _reset(*, setting: str, **_: Any) -> None:
    global _client
    if setting == "AUTH4":
        with _lock:
            _client = None


setting_changed.connect(_reset)


def authenticate(request: HttpRequest) -> AccessToken:
    """Verifies the request's Bearer access token. Raises :class:`~auth4.Auth4TokenError`."""
    return get_client().validate_authorization_header(request.headers.get("Authorization"))


def _error(status: int, error: str, headers: dict[str, str] | None = None) -> HttpResponse:
    response = JsonResponse({"error": error}, status=status)
    response["Cache-Control"] = "no-store"
    for name, value in (headers or {}).items():
        response[name] = value
    return response


def _check(
    request: HttpRequest, any_role: tuple[str, ...], allow_guests: bool, scopes: tuple[str, ...]
) -> HttpResponse | None:
    try:
        token = authenticate(request)
    except Auth4TokenError as error:
        if error.is_outage:
            return _error(503, "unavailable", {"Retry-After": "5"})
        return _error(401, "unauthorized", {"WWW-Authenticate": 'Bearer realm="auth4"'})
    if (
        (any_role and not token.has_any_role(any_role))
        or (token.is_guest and not allow_guests)
        or not all(token.has_scope(scope) for scope in scopes)
    ):
        return _error(403, "forbidden")
    # Django's HttpRequest accepts new attributes, as auth middleware sets request.user.
    setattr(request, "auth4", token)  # noqa: B010
    return None


def auth4_required(
    *, any_role: Iterable[str] = (), allow_guests: bool = True, scopes: Iterable[str] = ()
) -> Callable[[View], View]:
    """Decorates a sync or async view so it runs only with a valid access token, available as
    ``request.auth4``.

    :param any_role: When set, the token must carry at least one of these roles.
    :param allow_guests: Set False to refuse guest players.
    :param scopes: Scopes the token must all carry.
    """
    roles, required_scopes = tuple(any_role), tuple(scopes)

    def decorate(view: View) -> View:
        if iscoroutinefunction(view):

            @functools.wraps(view)
            async def async_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
                # Key fetches and introspection block, so they run off the event loop.
                refused = await sync_to_async(_check)(request, roles, allow_guests, required_scopes)
                return refused or await view(request, *args, **kwargs)

            return cast(View, async_wrapper)

        @functools.wraps(view)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            refused = _check(request, roles, allow_guests, required_scopes)
            return refused or view(request, *args, **kwargs)

        return cast(View, wrapper)

    return decorate
