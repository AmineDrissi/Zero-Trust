"""Signed ID cards for service-to-service calls.

Amine owns this file.

THE CONTRACT WITH ztlib/policy.py  (agree with Ishtiaq before writing code)
--------------------------------------------------------------------------
verify(token: str, expected_audience: str) -> str
    Returns the VERIFIED caller name on success.
    Raises IdentityError on any failure.

The caller name Ishtiaq uses in policy.evaluate() must come from this
function's return value and from nowhere else. It must never be read from a
header the caller sets on itself.

Every token carries:
    iss   who is calling
    aud   who it is for
    iat   issued at
    exp   expires (30 seconds)
    jti   one-time value, rejected if seen before
"""


class IdentityError(Exception):
    pass


def issue(subject: str, audience: str) -> str:
    raise NotImplementedError


def verify(token: str, expected_audience: str) -> str:
    raise NotImplementedError
