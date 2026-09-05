# Built-in packages
import json
import time
import typing

# Third-party packages
import pytest
from authlib.jose import JsonWebKey, JsonWebToken

ISSUER = "https://example.us.auth0.com/"
AUDIENCE = "https://example.us.auth0.com/api/v2/"
JWKS_URI = "https://example.us.auth0.com/.well-known/jwks.json"
KID = "test-kid"

jwt = JsonWebToken(["RS256"])


@pytest.fixture(scope="session")
def signing_key() -> typing.Any:
    return JsonWebKey.generate_key("RSA", 2048, is_private=True)


@pytest.fixture(scope="session")
def jwks_json(signing_key: typing.Any) -> str:
    jwk = signing_key.as_dict(is_private=False)
    jwk["kid"] = KID
    return json.dumps({"keys": [jwk]})


@pytest.fixture
def make_token(signing_key: typing.Any) -> typing.Callable[..., str]:
    def _make_token(payload: dict, *, header: typing.Optional[dict] = None) -> str:
        header = header or {"alg": "RS256", "kid": KID}
        token = jwt.encode(header, payload, signing_key)
        return token.decode("utf-8")

    return _make_token


@pytest.fixture
def base_payload() -> dict:
    now = int(time.time())
    return {
        "iss": ISSUER,
        "sub": "auth0|123456",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 3600,
    }
