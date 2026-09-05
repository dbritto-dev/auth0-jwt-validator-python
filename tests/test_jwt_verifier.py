import time

import pytest

from auth0_jwt_validator import (
    AccessTokenVerifier,
    IdTokenVerifier,
    InvalidClaimError,
    JwtVerifier,
    MissingClaimError,
)

from .conftest import AUDIENCE, ISSUER, JWKS_URI


@pytest.fixture
def id_token_verifier(jwks_json, monkeypatch):
    verifier = IdTokenVerifier(JWKS_URI, ISSUER, AUDIENCE)
    monkeypatch.setattr(verifier, "get_auth0_signing_keys", lambda jwks_uri: jwks_json)
    return verifier


@pytest.fixture
def access_token_verifier(jwks_json, monkeypatch):
    verifier = AccessTokenVerifier(JWKS_URI, ISSUER, AUDIENCE)
    monkeypatch.setattr(verifier, "get_auth0_signing_keys", lambda jwks_uri: jwks_json)
    return verifier


class TestJwtVerifier:
    def test_get_token_type_raises(self):
        verifier = JwtVerifier(JWKS_URI, ISSUER, AUDIENCE)
        with pytest.raises(NotImplementedError):
            verifier.get_token_type()

    def test_verify_payload_raises(self):
        verifier = JwtVerifier(JWKS_URI, ISSUER, AUDIENCE)
        with pytest.raises(NotImplementedError):
            verifier.verify_payload({})


class TestIdTokenVerifier:
    def test_get_token_type(self, id_token_verifier):
        assert id_token_verifier.get_token_type() == "ID token"

    def test_verify_succeeds(self, id_token_verifier, make_token, base_payload):
        token = make_token(base_payload)
        payload = id_token_verifier.verify(token)
        assert payload["sub"] == base_payload["sub"]

    def test_verify_with_nonce_succeeds(self, id_token_verifier, make_token, base_payload):
        base_payload["nonce"] = "some-random-string"
        token = make_token(base_payload)
        payload = id_token_verifier.verify(token, nonce="some-random-string")
        assert payload["nonce"] == "some-random-string"

    def test_verify_with_wrong_nonce_raises(self, id_token_verifier, make_token, base_payload):
        base_payload["nonce"] = "some-random-string"
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            id_token_verifier.verify(token, nonce="another-string")

    def test_verify_with_missing_nonce_raises(self, id_token_verifier, make_token, base_payload):
        token = make_token(base_payload)
        with pytest.raises(MissingClaimError):
            id_token_verifier.verify(token, nonce="some-random-string")

    def test_verify_with_organization_succeeds(self, id_token_verifier, make_token, base_payload):
        base_payload["org_id"] = "org_123"
        token = make_token(base_payload)
        payload = id_token_verifier.verify(token, organization="org_123")
        assert payload["org_id"] == "org_123"

    def test_verify_with_wrong_organization_raises(
        self, id_token_verifier, make_token, base_payload
    ):
        base_payload["org_id"] = "org_123"
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            id_token_verifier.verify(token, organization="org_456")

    def test_verify_with_max_age_succeeds(self, id_token_verifier, make_token, base_payload):
        base_payload["auth_time"] = int(time.time())
        token = make_token(base_payload)
        payload = id_token_verifier.verify(token, max_age=60 * 60 * 24)
        assert payload["auth_time"] == base_payload["auth_time"]

    def test_verify_with_max_age_expired_raises(self, id_token_verifier, make_token, base_payload):
        base_payload["auth_time"] = int(time.time()) - 1000
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            id_token_verifier.verify(token, max_age=10)

    def test_verify_with_multiple_audiences_requires_azp(
        self, id_token_verifier, make_token, base_payload
    ):
        base_payload["aud"] = [AUDIENCE, "https://example.us.auth0.com/api/other/"]
        token = make_token(base_payload)
        with pytest.raises(MissingClaimError):
            id_token_verifier.verify(token)

    def test_verify_with_multiple_audiences_and_azp_succeeds(
        self, id_token_verifier, make_token, base_payload
    ):
        base_payload["aud"] = [AUDIENCE, "https://example.us.auth0.com/api/other/"]
        base_payload["azp"] = AUDIENCE
        token = make_token(base_payload)
        payload = id_token_verifier.verify(token)
        assert payload["azp"] == AUDIENCE

    def test_verify_wrong_issuer_raises(self, id_token_verifier, make_token, base_payload):
        base_payload["iss"] = "https://another-tenant.us.auth0.com/"
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            id_token_verifier.verify(token)

    def test_verify_wrong_audience_raises(self, id_token_verifier, make_token, base_payload):
        base_payload["aud"] = "https://another-tenant.us.auth0.com/api/v2/"
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            id_token_verifier.verify(token)

    def test_verify_missing_audience_raises(self, id_token_verifier, make_token, base_payload):
        del base_payload["aud"]
        token = make_token(base_payload)
        with pytest.raises(MissingClaimError):
            id_token_verifier.verify(token)

    def test_verify_audience_not_in_list_raises(self, id_token_verifier, make_token, base_payload):
        base_payload["aud"] = [
            "https://another-tenant.us.auth0.com/api/v2/",
            "https://another-tenant.us.auth0.com/api/other/",
        ]
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            id_token_verifier.verify(token)

    def test_verify_with_multiple_audiences_and_wrong_azp_raises(
        self, id_token_verifier, make_token, base_payload
    ):
        base_payload["aud"] = [AUDIENCE, "https://example.us.auth0.com/api/other/"]
        base_payload["azp"] = "https://another-tenant.us.auth0.com/api/v2/"
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            id_token_verifier.verify(token)

    def test_verify_expired_token_raises(self, id_token_verifier, make_token, base_payload):
        base_payload["exp"] = int(time.time()) - 10
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            id_token_verifier.verify(token)

    def test_verify_missing_expiration_raises(self, id_token_verifier, make_token, base_payload):
        del base_payload["exp"]
        token = make_token(base_payload)
        with pytest.raises(MissingClaimError):
            id_token_verifier.verify(token)

    def test_verify_missing_organization_claim_raises(
        self, id_token_verifier, make_token, base_payload
    ):
        token = make_token(base_payload)
        with pytest.raises(MissingClaimError):
            id_token_verifier.verify(token, organization="org_123")

    def test_verify_missing_auth_time_raises(self, id_token_verifier, make_token, base_payload):
        token = make_token(base_payload)
        with pytest.raises(MissingClaimError):
            id_token_verifier.verify(token, max_age=60)

    def test_verify_missing_subject_raises(self, id_token_verifier, make_token, base_payload):
        del base_payload["sub"]
        token = make_token(base_payload)
        with pytest.raises(MissingClaimError):
            id_token_verifier.verify(token)

    def test_verify_empty_token_raises(self, id_token_verifier):
        with pytest.raises(MissingClaimError):
            id_token_verifier.verify("")


class TestAccessTokenVerifier:
    def test_get_token_type(self, access_token_verifier):
        assert access_token_verifier.get_token_type() == "access token"

    def test_verify_succeeds(self, access_token_verifier, make_token, base_payload):
        token = make_token(base_payload)
        payload = access_token_verifier.verify(token)
        assert payload["sub"] == base_payload["sub"]

    def test_verify_with_scopes_succeeds(self, access_token_verifier, make_token, base_payload):
        base_payload["scope"] = "profile calendar email"
        token = make_token(base_payload)
        payload = access_token_verifier.verify(token, required_scopes=["profile", "calendar"])
        assert payload["scope"] == "profile calendar email"

    def test_verify_with_missing_scope_claim_raises(
        self, access_token_verifier, make_token, base_payload
    ):
        token = make_token(base_payload)
        with pytest.raises(MissingClaimError):
            access_token_verifier.verify(token, required_scopes=["profile"])

    def test_verify_with_insufficient_scopes_raises(
        self, access_token_verifier, make_token, base_payload
    ):
        base_payload["scope"] = "profile"
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            access_token_verifier.verify(token, required_scopes=["profile", "calendar"])

    def test_verify_with_permissions_succeeds(
        self, access_token_verifier, make_token, base_payload
    ):
        base_payload["permissions"] = ["read:user", "delete:user"]
        token = make_token(base_payload)
        payload = access_token_verifier.verify(
            token, required_permissions=["read:user", "delete:user"]
        )
        assert payload["permissions"] == ["read:user", "delete:user"]

    def test_verify_with_missing_permissions_claim_raises(
        self, access_token_verifier, make_token, base_payload
    ):
        token = make_token(base_payload)
        with pytest.raises(MissingClaimError):
            access_token_verifier.verify(token, required_permissions=["read:user"])

    def test_verify_with_insufficient_permissions_raises(
        self, access_token_verifier, make_token, base_payload
    ):
        base_payload["permissions"] = ["read:user"]
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            access_token_verifier.verify(token, required_permissions=["read:user", "delete:user"])

    def test_verify_with_organization_succeeds(
        self, access_token_verifier, make_token, base_payload
    ):
        base_payload["org_id"] = "org_123"
        token = make_token(base_payload)
        payload = access_token_verifier.verify(token, organization="org_123")
        assert payload["org_id"] == "org_123"

    def test_verify_with_wrong_organization_raises(
        self, access_token_verifier, make_token, base_payload
    ):
        base_payload["org_id"] = "org_123"
        token = make_token(base_payload)
        with pytest.raises(InvalidClaimError):
            access_token_verifier.verify(token, organization="org_456")

    def test_verify_missing_issued_at_raises(
        self, access_token_verifier, make_token, base_payload
    ):
        del base_payload["iat"]
        token = make_token(base_payload)
        with pytest.raises(MissingClaimError):
            access_token_verifier.verify(token)
