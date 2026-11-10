"""auth4.dev server SDK for Python: verifies access tokens and ID tokens issued by an auth4.dev
tenant. It matches @auth4/sdk-server: same checks, same error codes, same introspect mode.

Framework integrations live in :mod:`auth4.fastapi` and :mod:`auth4.django`.
"""

from ._introspection import IntrospectionOptions
from ._rules import GUEST_CLAIM, METADATA_CLAIM, ROLES_CLAIM
from ._version import __version__
from .client import Auth4ServerClient, issuer_for, parse_bearer_token
from .errors import Auth4DiscoveryError, Auth4TokenError, TokenErrorCode
from .tokens import AccessToken, Discovery, IdToken, MetadataValue, has_any_role, has_role
from .transport import USER_AGENT, HttpRequest, HttpResponse, Transport, urllib_transport

__all__ = [
    "GUEST_CLAIM",
    "METADATA_CLAIM",
    "ROLES_CLAIM",
    "USER_AGENT",
    "AccessToken",
    "Auth4DiscoveryError",
    "Auth4ServerClient",
    "Auth4TokenError",
    "Discovery",
    "HttpRequest",
    "HttpResponse",
    "IdToken",
    "IntrospectionOptions",
    "MetadataValue",
    "TokenErrorCode",
    "Transport",
    "has_any_role",
    "has_role",
    "issuer_for",
    "parse_bearer_token",
    "urllib_transport",
    "__version__",
]
