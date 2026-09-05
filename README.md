# Auth0 JWT Validator

A JWT python package to validate tokens, scopes and permissions for Auth0 tokens.

- **Bug reports:** https://github.com/dbritto-dev/auth0-jwt-validator-python/issues
- **Source code:** https://github.com/dbritto-dev/auth0-jwt-validator-python

## Installation

### Install with uv

```sh
uv add auth0-jwt-validator
```

### Install with pip

```sh
pip install auth0-jwt-validator
```

## Requirements

- Python 3.10 or later

## Usage

### Validating an ID Token

```python
from auth0_jwt_validator import IdTokenVerifier

auth0_jwks_uri = "https://<auth0-tenant>.us.auth0.com/.well-known/jwks.json"
issuer = "https://<auth0-tenant>.us.auth0.com/"
audience = "https://<auth0-tenant>.us.auth0.com/api/v2/"

token_verifier = IdTokenVerifier(auth0_jwks_uri, issuer, audience)
token_verifier.verify("some-id-token")
```

The `verify` method also accepts `nonce`, `max_age` and `organization` to validate the
matching claims:

```python
token_verifier.verify("some-id-token", nonce="some-random-string")
token_verifier.verify("some-id-token", max_age=60 * 60 * 24)
token_verifier.verify("some-id-token", organization="some-organization")
```

### Validating an Access Token

```python
from auth0_jwt_validator import AccessTokenVerifier

auth0_jwks_uri = "https://<auth0-tenant>.us.auth0.com/.well-known/jwks.json"
issuer = "https://<auth0-tenant>.us.auth0.com/"
audience = "https://<auth0-tenant>.us.auth0.com/api/v2/"

token_verifier = AccessTokenVerifier(auth0_jwks_uri, issuer, audience)
token_verifier.verify("some-access-token")
```

The `verify` method also accepts `organization`, `required_scopes` and `required_permissions`:

```python
token_verifier.verify("some-access-token", organization="some-organization")
token_verifier.verify("some-access-token", required_scopes=["profile", "calendar"])
token_verifier.verify("some-access-token", required_permissions=["read:user", "delete:user"])
```

### Extracting a bearer token from a header

```python
from auth0_jwt_validator import get_token

get_token("Bearer super-secret-token")  # "super-secret-token"
```

Both verifiers raise `authlib.jose.errors.MissingClaimError` or
`authlib.jose.errors.InvalidClaimError` (re-exported from this package) when a claim is
missing or does not match the expected value.

## Development

This project uses [uv](https://docs.astral.sh/uv/) to manage dependencies and packaging.

```sh
uv sync --extra dev
```

Common tasks are wired up through [nox](https://nox.thea.codes/):

```sh
uvx nox -s lint
uvx nox -s test
uvx nox -s type_check
uvx nox -s security_test
```

## License

MIT — see [LICENSE](LICENSE).
