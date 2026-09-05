import pytest

from auth0_jwt_validator import get_token


@pytest.mark.parametrize(
    ("authorization_header", "expected"),
    [
        ("Bearer super-secret-token", "super-secret-token"),
        ("bearer super-secret-token", "super-secret-token"),
        ("BEARER super-secret-token", "super-secret-token"),
        ("Bearer abc.def-ghi_123", "abc.def-ghi_123"),
        (None, None),
        ("", None),
        ("Token super-secret-token", None),
        ("Bearer super-secret-token extra-secret-token", None),
        ("Bearer ", None),
        ("Bearer", None),
        (123, None),
    ],
)
def test_get_token(authorization_header, expected):
    assert get_token(authorization_header) == expected
