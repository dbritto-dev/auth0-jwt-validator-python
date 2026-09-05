# Built-in packages
import re
import typing

# Third-party packages

# Local packages


def get_token(authorization_header: str) -> typing.Optional[str]:
    """
    Get a token from a authorization header with a bearer authentication schema.

    Parameters
    ----------
    authorization_header : str
        The authorization header which one we want to get the bearer token.

    Returns
    -------
    token : str or None
        The bearer token is `None` only when the authorization header mismatch
        the bearer authentication schema for bearer tokens.

    Examples
    --------

    >>> from auth0_jwt_validator import get_token
    >>> auth_header = "Bearer super-secret-token"
    >>> get_token(auth_header)
    "super-secret-token"

    >>> from auth0_jwt_validator import get_token
    >>> auth_header = None
    >>> get_token(auth_header)
    None

    >>> from auth0_jwt_validator import get_token
    >>> auth_header = "Token super-secret-token"
    >>> get_token(auth_header)
    None

    >>> from auth0_jwt_validator import get_token
    >>> auth_header = "Bearer super-secret-token extra-secret-token"
    >>> get_token(auth_header)
    None

    >>> from auth0_jwt_validator import get_token
    >>> auth_header = "Bearer "
    >>> get_token(auth_header)
    None
    """

    if not authorization_header or not isinstance(authorization_header, str):
        return None

    if not re.match(r"^bearer", authorization_header, re.IGNORECASE):
        return None

    # check bearer format
    if not re.match(r"^bearer [\w\.-]+$", authorization_header, re.IGNORECASE):
        return None

    _, token = authorization_header.split()

    return token
