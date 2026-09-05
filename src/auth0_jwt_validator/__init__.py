"""Python Auth0 JWT Validator

A JWT python package to validate tokens, scopes and permissions for Auth0 tokens.

Examples
--------

Validating ID Token

>>> from auth0_jwt_validator import IdTokenVerifier
>>> auth0_jwks_uri = "https://<auth0-tenant>.us.auth0.com/.well-known/jwks.json"
>>> issuer = "https://<auth0-tenant>.us.auth0.com/"
>>> audience = "https://<auth0-tenant>.us.auth0.com/api/v2/"
>>> token_verifier = IdTokenVerifier(auth0_jwks_uri, issuer, audience)
>>> token_verifier.verify("some-id-token")

Validating ID Token and nonce

>>> from auth0_jwt_validator import IdTokenVerifier
>>> auth0_jwks_uri = "https://<auth0-tenant>.us.auth0.com/.well-known/jwks.json"
>>> issuer = "https://<auth0-tenant>.us.auth0.com/"
>>> audience = "https://<auth0-tenant>.us.auth0.com/api/v2/"
>>> token_verifier = IdTokenVerifier(auth0_jwks_uri, issuer, audience)
>>> token_verifier.verify("some-id-token", nonce="some-random-string")

Validating ID Token and max_age

>>> from auth0_jwt_validator import IdTokenVerifier
>>> auth0_jwks_uri = "https://<auth0-tenant>.us.auth0.com/.well-known/jwks.json"
>>> issuer = "https://<auth0-tenant>.us.auth0.com/"
>>> audience = "https://<auth0-tenant>.us.auth0.com/api/v2/"
>>> token_verifier = IdTokenVerifier(auth0_jwks_uri, issuer, audience)
>>> token_verifier.verify("some-id-token", max_age=60 * 60 * 24)

Validating ID Token and organization

>>> from auth0_jwt_validator import IdTokenVerifier
>>> auth0_jwks_uri = "https://<auth0-tenant>.us.auth0.com/.well-known/jwks.json"
>>> issuer = "https://<auth0-tenant>.us.auth0.com/"
>>> audience = "https://<auth0-tenant>.us.auth0.com/api/v2/"
>>> token_verifier = IdTokenVerifier(auth0_jwks_uri, issuer, audience)
>>> token_verifier.verify("some-id-token", organization="some-organization")

Validating Access Token

>>> from auth0_jwt_validator import AccessTokenVerifier
>>> auth0_jwks_uri = "https://<auth0-tenant>.us.auth0.com/.well-known/jwks.json"
>>> issuer = "https://<auth0-tenant>.us.auth0.com/"
>>> audience = "https://<auth0-tenant>.us.auth0.com/api/v2/"
>>> token_verifier = AccessTokenVerifier(auth0_jwks_uri, issuer, audience)
>>> token_verifier.verify("some-access-token")

Validating Access Token and organization

>>> from auth0_jwt_validator import AccessTokenVerifier
>>> auth0_jwks_uri = "https://<auth0-tenant>.us.auth0.com/.well-known/jwks.json"
>>> issuer = "https://<auth0-tenant>.us.auth0.com/"
>>> audience = "https://<auth0-tenant>.us.auth0.com/api/v2/"
>>> token_verifier = AccessTokenVerifier(auth0_jwks_uri, issuer, audience)
>>> token_verifier.verify("some-access-token", organization="some-organization")

Validating Access Token and scopes

>>> from auth0_jwt_validator import AccessTokenVerifier
>>> auth0_jwks_uri = "https://<auth0-tenant>.us.auth0.com/.well-known/jwks.json"
>>> issuer = "https://<auth0-tenant>.us.auth0.com/"
>>> audience = "https://<auth0-tenant>.us.auth0.com/api/v2/"
>>> token_verifier = AccessTokenVerifier(auth0_jwks_uri, issuer, audience)
>>> token_verifier.verify("some-access-token", required_scopes=["profile", "calendar"])

Validating Access Token and permissions

>>> from auth0_jwt_validator import AccessTokenVerifier
>>> auth0_jwks_uri = "https://<auth0-tenant>.us.auth0.com/.well-known/jwks.json"
>>> issuer = "https://<auth0-tenant>.us.auth0.com/"
>>> audience = "https://<auth0-tenant>.us.auth0.com/api/v2/"
>>> token_verifier = AccessTokenVerifier(auth0_jwks_uri, issuer, audience)
>>> token_verifier.verify("some-access-token", required_permissions=["read:user", "delete:user"])
"""

__version__ = "1.2.0"

from .http_bearer import get_token  # noqa
from .jwt_verifier import (  # noqa
    AccessTokenVerifier,
    IdTokenVerifier,
    InvalidClaimError,
    JwtVerifier,
    MissingClaimError,
    jwt,
)
