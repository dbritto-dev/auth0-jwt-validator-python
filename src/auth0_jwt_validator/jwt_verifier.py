# Built-in packages
import time
import typing
import urllib.parse
import urllib.request

# Third-party packages
from authlib.jose import JsonWebToken
from authlib.jose.errors import InvalidClaimError, MissingClaimError

# Local packages

jwt = JsonWebToken(["RS256"])


class JwtVerifier:
    """
    Attributes
    ----------
    jwks_uri : str
        The JSON Web Key Set URI where the public keys are located.
    issuer : str
        The client that issued the JWT.
    audience : str
        The recipient that the JWT is intended for.

    Methods
    -------
    get_token_type()
        Return the token type used by the verify methods. This method raise an
        error because this method should be implemented in the  sub-class.

    verify(auth0_token)
        Return the payload from an access token or ID token

    get_auth0_signing_keys(jwks_uri)
        Return the signing keys from a given JSON Web Key Set URI.

    verify_payload(*args, **kwargs)
        This method raise an error because this method should be implemented in
        the sub-class.

    Examples
    --------
    Custom Token Verifier

    ```python
    class CustomTokenVerifier(JwtVerifier):
        def get_token_type():
            return "custom token"

        def verify(self, auth0_token: str) -> dict:
            payload: dict = super().verify(auth0_token)
            return payload

        def verify_payload(self, payload: dict) -> None:
            # validate just the issuer
            self.verify_issuer(payload)
    ```
    """

    def __init__(
        self,
        jwks_uri: str,
        issuer: str,
        audience: str,
        *,
        leeway: int = 0,
    ) -> None:
        """
        Parameters
        ----------
        jwks_uri : str
            The JSON Web Key Set URI where the public keys are located.
        issuer : str
            The client that issued the JWT.
        audience : str
            The recipient that the JWT is intended for.
        """

        self.jwks_uri = jwks_uri
        self.issuer = issuer
        self.audience = audience
        self.leeway = leeway

    def get_token_type(self) -> str:
        """
        Raises
        ------
        NotImplementedError
            Raise an error because this method should be implemented in a
            sub-class.
        """

        raise NotImplementedError("get_token_type method should be implementend")

    def get_auth0_signing_keys(self, jwks_uri: str) -> str:  # pragma: no cover
        """

        Parameters
        ----------
        jwks_uri : str
            The JSON Web Key Set URI where the public keys are located.

        Returns
        -------
        auth0_signing_keys : str
            Return the auth0 public keys as JSON.
        """

        # Fix for Bandit (B310): https://bandit.readthedocs.io/en/1.7.4/blacklists/blacklist_calls.html#b310-urllib-urlopen
        https_jwks_uri = urllib.parse.urlparse(jwks_uri)._replace(scheme="https").geturl()

        with urllib.request.urlopen(https_jwks_uri) as r:  # nosec B310 # noqa: S310
            return r.read().decode("utf-8")

    def verify(self, auth0_token: str) -> typing.Mapping[str, typing.Any]:
        if not auth0_token:
            return {}

        claims = jwt.decode(auth0_token, self.get_auth0_signing_keys(self.jwks_uri))
        return claims.copy()

    def verify_payload(self, *args, **kwargs) -> None:
        """
        Raises
        ------
        NotImplementedError
            Raise an error because this method should be implemented in a
            sub-class.
        """

        raise NotImplementedError("verify_payload method should be implementend")

    def verify_issuer(self, payload: typing.Mapping[str, typing.Any]) -> None:
        """
        Verify the issuer

        Parameters
        ----------
        payload : dict
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.
        """

        if "iss" not in payload or not isinstance(payload["iss"], str):
            raise MissingClaimError(
                f"Issuer (iss) claim must be a string present in the {self.get_token_type()}"
            )
        if payload["iss"] != self.issuer:
            raise InvalidClaimError(
                f"Issuer (iss) claim mismatch in the {self.get_token_type()}; expected"
                f" {self.issuer}, found  {payload['iss']}"
            )

    def verify_subject(self, payload: typing.Mapping[str, typing.Any]) -> None:
        """
        Verify the subject

        Parameters
        ----------
        payload : dict
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.
        """

        if "sub" not in payload or not isinstance(payload["sub"], str):
            raise MissingClaimError(
                f"Subject (sub) claim must be a string present in the {self.get_token_type()}"
            )

    def verify_audience(self, payload: typing.Mapping[str, typing.Any]) -> None:
        """
        Verify the audience

        Parameters
        ----------
        payload : dict
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.
        """

        if "aud" not in payload or not isinstance(payload["aud"], (str, list)):
            raise MissingClaimError(
                "Audience (aud) claim must be a string or array of strings present in the "
                f"{self.get_token_type()}"
            )

        if isinstance(payload["aud"], list) and self.audience not in payload["aud"]:
            raise InvalidClaimError(
                f"Audience (aud) claim mismatch in the {self.get_token_type()}; expected "
                f"{self.audience} but was not one of {', '.join(payload['aud'])}"
            )

        elif isinstance(payload["aud"], str) and payload["aud"] != self.audience:
            raise InvalidClaimError(
                f"Audience (aud) claim mismatch in the {self.get_token_type()}; expected"
                f" {self.audience} but found {payload['aud']}"
            )

    def verify_expiration_time(self, payload: typing.Mapping[str, typing.Any]) -> None:
        """
        Verify the expiration time

        Parameters
        ----------
        payload : dict
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.
        """

        now = time.time()
        leeway = self.leeway

        # Expires at
        if "exp" not in payload or not isinstance(payload["exp"], int):
            raise MissingClaimError(
                "Expiration Time (exp) claim must be a number present in the"
                f" {self.get_token_type()}"
            )

        exp_time = payload["exp"] + leeway
        if now > exp_time:
            raise InvalidClaimError(
                f"Expiration Time (exp) claim error in the {self.get_token_type()}; "
                f"current time ({now}) is after expiration time ({exp_time})"
            )

    def verify_issued_at_time(self, payload: typing.Mapping[str, typing.Any]) -> None:
        """
        Verify the issued at time

        Parameters
        ----------
        payload : dict
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.
        """

        if "iat" not in payload or not isinstance(payload["iat"], int):
            raise MissingClaimError(
                f"Issued At (iat) claim must be a number present in the {self.get_token_type()}"
            )

    def verify_azp(self, payload: typing.Mapping[str, typing.Any]) -> None:
        """
        Verify the authorized party

        Parameters
        ----------
        payload : dict
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.
        """

        if isinstance(payload["aud"], list) and len(payload["aud"]) > 1:
            if "azp" not in payload or not isinstance(payload["azp"], str):
                raise MissingClaimError(
                    "Authorized Party (azp) claim must be a string present in the "
                    f"{self.get_token_type()} when Audience (aud) claim has multiple values"
                )

            if payload["azp"] != self.audience:
                raise InvalidClaimError(
                    f"Authorized Party (azp) claim mismatch in the {self.get_token_type()};"
                    f" expected {self.audience}, found {payload['azp']}"
                )

    def verify_org_id(self, payload: typing.Mapping[str, typing.Any], organization: str) -> None:
        """
        Verify the organization id

        Parameters
        ----------
        payload : dict
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.
        organization : str
            The organization that issued the token.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.
        """

        if "org_id" not in payload or not isinstance(payload["org_id"], str):
            raise MissingClaimError(
                "Organization (org_id) claim must be a string present in the"
                f" {self.get_token_type()}"
            )

        if payload["org_id"] != organization:
            raise InvalidClaimError(
                f"Organization (org_id) claim mismatch in the {self.get_token_type()}; expected  "
                f"{organization}, found {payload['org_id']}"
            )

    def verify_nonce(self, payload: typing.Mapping[str, typing.Any], nonce: str):
        """
        Verify the nonce

        Parameters
        ----------
        payload : dict
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.
        nonce : str
            The valued associated to the Client session and the ID token.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.
        """

        if "nonce" not in payload or not isinstance(payload["nonce"], str):
            raise MissingClaimError(
                f"Nonce (nonce) claim must be a string present in the {self.get_token_type()}"
            )

        if payload["nonce"] != nonce:
            raise InvalidClaimError(
                f"Nonce (nonce) claim mismatch in the {self.get_token_type()}; expected {nonce}, "
                f"found {payload['nonce']}"
            )

    def verify_auth_time(self, payload: typing.Mapping[str, typing.Any], max_age: int):
        """
        Verify the authentication time

        Parameters
        ----------
        payload : dict
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.
        max_age : int
            The max_age help us to customize when a token should expire.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.
        """

        now = time.time()
        leeway = self.leeway

        if "auth_time" not in payload or not isinstance(payload["auth_time"], int):
            raise MissingClaimError(
                "Authentication Time (auth_time) claim must be a number present in the"
                f" {self.get_token_type()} when Max Age (max_age) is specified"
            )

        auth_valid_until = payload["auth_time"] + max_age + leeway
        if now > auth_valid_until:
            raise InvalidClaimError(
                f"Authentication Time (auth_time) claim in the {self.get_token_type()} indicates"
                " that too much time has passed since the last end-user authentication. Current"
                f" time ({now}) is after last auth at ({auth_valid_until})"
            )


class IdTokenPayload(typing.TypedDict):
    """
    Attributes
    ----------
    iss : str
        The "iss" (issuer) claim identifies the principal that issued the JWT.
        `Read more<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1>`_.
    sub : str
        The "sub" (subject) claim identifies the principal that is the subject
         of the JWT. `Read more<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2>`_.
    aud : str, list of str
        The "aud" (audience) claim identifies the recipients that the JWT is
        intended for. `Read more<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3>`_.
    exp : int
        The "exp" (expiration time) claim identifies the expiration time on or
        after which the JWT MUST NOT be accepted for processing. `Read more<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4>`_.
    iat : int
        The "iat" (issued at) claim identifies the time at which the JWT was
        issued. `Read more<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6>`_.
    name : str
        The "name" claim identifies the full name. `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    given_name : str
        The "given_name" claim identifies the given name(s) or first name(s). `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    family_name : str
        The "family_name" claim identifies the surname(s) or last name(s). `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    gender : str, {'male', 'female'}
        The "gender" claim identifies the gender. `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    birthdate : str
        The "birthdate" claim identifies the birthday. `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    email : str
        The "email" claim identifies the preferred e-mail address. `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    picture : str
        The "picture" claim identifies the profile picture URL. `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    nonce : str, optional
        The "nonce" claim identifies the valued used to associate a Client
        session with an ID Token, and to mitigate replay attacks. `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    auth_time : int, optional
        The "auth_time" (authentication time) claim identifies the time when the
        End-User authentication occurred. `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    """

    iss: str
    sub: str
    aud: typing.Union[str, typing.List[str]]
    exp: int
    iat: int
    name: str
    given_name: str
    family_name: str
    gender: typing.Literal["male", "female"]
    birthdate: str
    email: str
    picture: str
    nonce: typing.Optional[str]
    auth_time: typing.Optional[int]


class IdTokenVerifier(JwtVerifier):
    """
    Attributes
    ----------
    jwks_uri : str
        The JSON Web Key Set URI where the public keys are located.
    issuer : str
        The client that issued the JWT.
    audience : str
        The recipient that the JWT is intended for.

    Methods
    -------
    get_token_type()
        Return the token type used by the verify methods.

    get_auth0_signing_keys(jwks_uri)
        Return the public keys located under the given JSON Web Key Set URI.

    verify(auth_token[, nonce, max_age, organization])
        Return the payload or raise an error when on of the verifications fails.

    verify_payload(payload[, nonce, max_age, organization])
        Raise an error when one of the verification fails.

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
    """

    def get_token_type(self) -> str:
        """
        Returns
        -------
        token_type : str
            Return the token type (ID token or access token) used by the verify
            methods.
        """

        return "ID token"

    def verify(
        self,
        auth0_token: str,
        *,
        nonce: typing.Optional[str] = None,
        max_age: typing.Optional[int] = None,
        organization: typing.Optional[str] = None,
    ) -> IdTokenPayload:
        """
        Parameters
        ----------
        auth0_token : str
            The ID token.

        Other Parameters
        ----------------
        nonce : str, default None
            Lorem.
        max_age : int, default None
            Lorem.
        organization : str, default None
            The organization that issued the token.

        Returns
        -------
        payload: `IdTokenPayload`
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.

        See Also
        --------
        IdTokenPayload
        """

        payload: IdTokenPayload = super().verify(auth0_token)  # type: ignore
        self.verify_payload(payload, nonce=nonce, max_age=max_age, organization=organization)

        return payload

    def verify_payload(
        self,
        payload: IdTokenPayload,
        *,
        nonce: typing.Optional[str] = None,
        max_age: typing.Optional[int] = None,
        organization: typing.Optional[str] = None,
    ) -> None:
        """
        Parameters
        ----------
        payload : `IdTokenPayload`
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.

        Other Parameters
        ----------------
        nonce : str, default None
            Lorem.
        max_age : int, default None
            Lorem.
        organization : str, default None
            The organization that issued the token.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is
            raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.

        See Also
        --------
        IdTokenPayload
        """

        # Issuer
        self.verify_issuer(payload)

        # Subject
        self.verify_subject(payload)

        # Audience
        self.verify_audience(payload)

        # Expires at
        self.verify_expiration_time(payload)

        # Issued at
        self.verify_issued_at_time(payload)

        # Nonce
        if nonce:
            self.verify_nonce(payload, nonce)

        # Organization
        if organization:
            self.verify_org_id(payload, organization)

        # Authorized party
        self.verify_azp(payload)

        # Authentication time
        if max_age:
            self.verify_auth_time(payload, max_age)


class AccessTokenPayload(typing.TypedDict):
    """
    Attributes
    ----------
    iss : str
        The "iss" (issuer) claim identifies the principal that issued the JWT.
        `Read more<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1>`_.
    sub : str
         The "sub" (subject) claim identifies the principal that is the subject
         of the JWT. `Read more<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2>`_.
    aud : str, list of str
        The "aud" (audience) claim identifies the recipients that the JWT is
        intended for. `Read more<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3>`_.
    azp : str
        The "azp" (authorized party) claim identifies the party to which the ID
        Token was issued. `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    exp : int
        The "exp" (expiration time) claim identifies the expiration time on or
        after which the JWT MUST NOT be accepted for processing. `Read more<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4>`_.
    iat : int
        The "iat" (issued at) claim identifies the time at which the JWT was
        issued. `Read more<https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6>`_.
    scope : str
        The "scope" claim identifies the space-separated list of scopes
        associated with the token. `Read more<https://www.iana.org/assignments/jwt/jwt.xhtml>`_.
    gty : str
        The "gty" (grant type) claim identifies the grant type used to create
        the token.
    permissions : list of str, optional
        The "permissions" claim identifies the list of permissions associated to
        the current user.
    org_id : str, optional
        The "org_id" (organization id) claim identifies the organization under
        which the JWT was issued.
    """

    iss: str
    sub: str
    aud: typing.Union[str, typing.List[str]]
    azp: str
    exp: int
    iat: int
    scope: str
    gty: str
    permissions: typing.Optional[typing.List[str]]
    org_id: typing.Optional[str]


class AccessTokenVerifier(JwtVerifier):
    """
    Attributes
    ----------
    jwks_uri : str
        The JSON Web Key Set URI where the public keys are located.
    issuer : str
        The client that issued the JWT.
    audience : str
        The recipient that the JWT is intended for.

    Methods
    -------
    get_token_type()
        Return the token type used by the verify methods.

    get_auth0_signing_keys(jwks_uri)
        Return the public keys located under the given JSON Web Key Set URI.

    verify(auth_token[,organization, required_scopes, required_permissions])
        Return the payload or raise an error.

    verify_payload(payload[,organization, required_scopes, required_permissions])
        Raise an error when one of the verification fails.

    Examples
    --------
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

    def get_token_type(self) -> str:
        """
        Returns
        -------
        token_type : str
            Return the token type (ID token or access token) used by the verify
            methods.
        """

        return "access token"

    def verify(
        self,
        auth0_token: str,
        *,
        organization: typing.Optional[str] = None,
        required_scopes: typing.Optional[typing.List[str]] = None,
        required_permissions: typing.Optional[typing.List[str]] = None,
    ) -> AccessTokenPayload:
        """
        Parameters
        -----------
        auth_token : str
            The access token.

        Other Parameters
        ----------------
        organization : str, default None
            The organization that issued the token.
        required_scopes : list of str, default None
            The list of scopes which are required to be in the payload.
        required_permissions : list of str, default None
            The list of permissions which are required to be in the payload.

        Returns
        -------
        payload : `AccessTokenPayload`
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.

        Raises
        -------
        MissingClaimError
            If some field in the claim (payload) is missing this error is raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.

        See Also
        --------
        AccessTokenPayload
        """

        payload: AccessTokenPayload = super().verify(auth0_token)  # type: ignore
        self.verify_payload(
            payload,
            organization=organization,
            required_scopes=required_scopes,
            required_permissions=required_permissions,
        )

        return payload

    def verify_payload(
        self,
        payload: AccessTokenPayload,
        *,
        organization: typing.Optional[str] = None,
        required_scopes: typing.Optional[typing.List[str]] = None,
        required_permissions: typing.Optional[typing.List[str]] = None,
    ) -> None:
        """
        Parameters
        ----------
        payload : `AccessTokenPayload`
            The payload which contains the claims. Claims are statements about
            an entity (typically, the user) and additional data.

        Other Parameters
        ----------------
        organization : str, default None
            The organization that issued the token.
        required_scopes : list of str, default None
            The list of scopes which are required to be in the payload.
        required_permissions : list of str, default None
            The list of permissions which are required to be in the payload.

        Returns
        -------
        None

        Raises
        ------
        MissingClaimError
            If some field in the claim (payload) is missing this error is raised.
        InvalidClaimError
            If some field in the claim (payload) doesn't match what's expected
            this error is raised.

        See Also
        --------
        AccessTokenPayload
        """

        # Issuer
        self.verify_issuer(payload)

        # Subject
        self.verify_subject(payload)

        # Audience
        self.verify_audience(payload)

        # Expires at
        self.verify_expiration_time(payload)

        # Issued at
        self.verify_issued_at_time(payload)

        # Organization
        if organization:
            self.verify_org_id(payload, organization)

        if required_scopes:
            self._verify_scopes(payload, required_scopes)

        if required_permissions:
            self._verify_permissions(payload, required_permissions)

    def _verify_scopes(
        self, payload: AccessTokenPayload, required_scopes: typing.List[str]
    ) -> None:
        if "scope" not in payload or not isinstance(payload["scope"], str):
            raise MissingClaimError(
                f"Scope (scope) claim must be a string present in the {self.get_token_type()}"
            )

        scopes = payload["scope"].split()
        has_enough_scopes = set(scopes).issuperset(required_scopes)

        if not has_enough_scopes:
            raise InvalidClaimError(
                f"Scope (scope) claim mismatch in the {self.get_token_type()}; expected at least "
                f"these {', '.join(required_scopes)} but was found these {', '.join(scopes)}"
            )

    def _verify_permissions(
        self, payload: AccessTokenPayload, required_permissions: typing.List[str]
    ) -> None:
        if "permissions" not in payload or not isinstance(payload["permissions"], list):
            raise MissingClaimError(
                "Permissions (permissions) claim must be an array of strings present in the "
                f"{self.get_token_type()}"
            )

        permissions = payload["permissions"]
        has_enough_scopes = set(permissions).issuperset(required_permissions)

        if not has_enough_scopes:
            raise InvalidClaimError(
                f"Permissions (permissions) claim mismatch in the {self.get_token_type()}; "
                f"expected at least these {', '.join(required_permissions)} but was found these "
                f"{', '.join(permissions)}"
            )
