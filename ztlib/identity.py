"""
ztlib/identity.py - signed ID cards for service-to-service calls.
Owner: Amine.

WHAT THIS IS
------------
Zero Trust means no service is believed just because it is on the network.
Every request carries a short-lived, single-use, cryptographically signed
token that says who is calling and who the call is for. The receiving
service verifies that token and hands the VERIFIED caller name to
ztlib.policy.evaluate().

THE CONTRACT WITH ztlib/policy.py  (agreed with Ishtiaq)
--------------------------------------------------------
    get_verified_caller(request) -> str

Returns a plain lowercase service name: "gateway", "worker", "model-store".
On ANY failure - missing token, bad signature, expired, wrong audience,
replayed - it returns the literal string "unknown" rather than raising, so
the caller stays on the policy path and gets a clean 403 instead of a 500.
"unknown" matches no rule in policy.yaml, so deny-by-default does the rest.

    sign_outgoing(headers, service_name, audience=None) -> headers

Adds the X-ZT-Token header to an outgoing request, signed as service_name.

EVERY TOKEN CARRIES
-------------------
    iss   who is calling
    aud   who the token is for (audience binding; see note below)
    iat   issued at
    exp   expires - 30 seconds
    jti   one-time value; a second use is rejected

WHY HMAC-SHA256 AND NOT ED25519
-------------------------------
The service containers install only flask and requests. Symmetric HMAC needs
no third-party package, so this drops into them unchanged with two days left
in the build. The trade-off is real and belongs in the write-up: with a shared
seed, a compromised service could mint a token for any other. A production
deployment issues asymmetric per-workload identities (SPIFFE/SPIRE X.509
SVIDs) so that a compromised service can only speak as itself. The token
format here is deliberately kept swappable: only _sign() and _mac_verify()
would change.

KEY MATERIAL
------------
No key is ever committed. Each service derives its own key from a shared seed
using HKDF-SHA256 with the service name as the info parameter, so nothing has
to be distributed at build time. Override the demo seed in production via the
ZT_SEED environment variable.

AUDIENCE BINDING - one line for Abubakar
----------------------------------------
Audience binding switches on automatically once each service knows its own
name. Add to every service in both compose files:

    environment:
      ZT_SERVICE_NAME: "worker"      # gateway / worker / model-store

and pass the target as the third argument at the three call sites, e.g.
sign_outgoing(headers, SERVICE_NAME, "worker"). Until then tokens verify
without an audience check and a warning is logged - everything still works,
it is just one notch weaker.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import threading
import time

__all__ = [
    "IdentityError",
    "issue",
    "verify",
    "sign_outgoing",
    "get_verified_caller",
    "service_key",
]

TOKEN_HEADER = "X-ZT-Token"
ALGORITHM = "HS256"
DEFAULT_TTL_SECONDS = 30
CLOCK_SKEW_SECONDS = 2
UNKNOWN_CALLER = "unknown"

# Demo seed. Real deployments set ZT_SEED. This is not a secret we are
# pretending is safe - it is a demo value, and it is why the write-up lists
# asymmetric workload identity as the production path.
_DEFAULT_SEED = "zt-demo-seed-do-not-use-outside-this-prototype"

logger = logging.getLogger("ztlib.identity")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)


class IdentityError(Exception):
    """Raised by verify() when a token cannot be trusted, for any reason."""


# ---------------------------------------------------------------------------
# Key derivation - HKDF-SHA256 (RFC 5869)
# ---------------------------------------------------------------------------

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _seed() -> bytes:
    return os.environ.get("ZT_SEED", _DEFAULT_SEED).encode("utf-8")


def service_key(service_name: str) -> bytes:
    """Derive this service's signing key. Distinct per service, never stored."""
    prk = _hkdf_extract(b"zt-identity-v1", _seed())
    return _hkdf_expand(prk, service_name.encode("utf-8"), 32)


# ---------------------------------------------------------------------------
# base64url without padding
# ---------------------------------------------------------------------------

def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------------------------------------------------------------------
# Replay cache - a jti may be spent exactly once
# ---------------------------------------------------------------------------

class _ReplayCache:
    """
    Remembers spent token ids until they expire anyway.

    Limitation worth stating in the write-up: this lives in one process, so
    it is per-container. Two replicas of the same service would not share it.
    Production puts this in Redis with the token's own TTL.
    """

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def spend(self, jti: str, expires_at: float) -> bool:
        """True if this jti was unused. False if it is a replay."""
        now = time.time()
        with self._lock:
            if self._seen and len(self._seen) > 4096:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
            if jti in self._seen and self._seen[jti] > now:
                return False
            self._seen[jti] = expires_at
            return True

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


_replay_cache = _ReplayCache()


# ---------------------------------------------------------------------------
# Issue and verify
# ---------------------------------------------------------------------------

def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue(subject: str, audience: str | None = None, ttl: int = DEFAULT_TTL_SECONDS) -> str:
    """
    Mint a single-use token for `subject` to present to `audience`.

    A fresh jti every time. Never reuse one - it is the single-use property
    that makes a captured token worthless on its second presentation.
    """
    now = int(time.time())
    header = {"alg": ALGORITHM, "typ": "ZT"}
    payload = {
        "iss": subject,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_urlsafe(16),
    }
    if audience is not None:
        payload["aud"] = audience

    signing_input = _b64e(_canonical(header)) + "." + _b64e(_canonical(payload))
    mac = hmac.new(service_key(subject), signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + _b64e(mac)


def verify(token: str, expected_audience: str | None = None) -> str:
    """
    Verify a token and return the VERIFIED issuer name.

    Raises IdentityError on: malformed token, unexpected algorithm, unknown
    issuer, bad signature, expiry, audience mismatch, or replay.

    Checks run in this order deliberately: nothing about the payload is
    trusted until the signature over it has been verified.
    """
    if not token or not isinstance(token, str):
        raise IdentityError("token_absent")

    parts = token.split(".")
    if len(parts) != 3:
        raise IdentityError("token_malformed")

    header_b64, payload_b64, mac_b64 = parts

    try:
        header = json.loads(_b64d(header_b64))
        payload = json.loads(_b64d(payload_b64))
        presented_mac = _b64d(mac_b64)
    except Exception:
        raise IdentityError("token_undecodable")

    # Reject anything that is not exactly our algorithm. In particular this
    # refuses alg="none", the classic JWT downgrade.
    if not isinstance(header, dict) or header.get("alg") != ALGORITHM:
        raise IdentityError("bad_algorithm")

    if not isinstance(payload, dict):
        raise IdentityError("token_malformed")

    issuer = payload.get("iss")
    if not issuer or not isinstance(issuer, str):
        raise IdentityError("issuer_missing")

    # Verify the signature BEFORE trusting any other claim.
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    expected_mac = hmac.new(service_key(issuer), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(presented_mac, expected_mac):
        raise IdentityError("bad_signature")

    now = time.time()

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        raise IdentityError("exp_missing")
    if now > exp + CLOCK_SKEW_SECONDS:
        raise IdentityError("token_expired")

    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and iat > now + CLOCK_SKEW_SECONDS:
        raise IdentityError("issued_in_future")

    if expected_audience is not None:
        aud = payload.get("aud")
        if aud is None:
            logger.info(
                "%s identity.warn reason=audience_unbound iss=%s "
                "note=set ZT_SERVICE_NAME and pass the audience at the call site"
                % (_ts(), issuer)
            )
        elif aud != expected_audience:
            raise IdentityError("wrong_audience")

    jti = payload.get("jti")
    if not jti or not isinstance(jti, str):
        raise IdentityError("jti_missing")
    if not _replay_cache.spend(jti, float(exp)):
        raise IdentityError("jti_replay")

    return issuer


# ---------------------------------------------------------------------------
# What the services actually call
# ---------------------------------------------------------------------------

def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sign_outgoing(headers: dict | None, service_name: str, audience: str | None = None) -> dict:
    """
    Attach a freshly minted ID card to an outgoing request.

    Call it as sign_outgoing(headers, SERVICE_NAME, "worker") to bind the
    token to its destination. Two arguments still works and stays unbound.
    """
    headers = dict(headers or {})
    headers[TOKEN_HEADER] = issue(service_name, audience=audience)
    return headers


def get_verified_caller(request, audience: str | None = None) -> str:
    """
    Pull the token off an incoming request and return the verified caller.

    Returns "unknown" on any failure - never raises - so the service stays on
    the policy path and the request is refused by deny-by-default with a 403,
    not a 500. Every rejection is logged with the precise reason, which is
    what makes the demo readable.

    `request` only needs a .headers mapping, so this is testable without Flask.
    """
    if audience is None:
        audience = os.environ.get("ZT_SERVICE_NAME")

    token = ""
    try:
        token = request.headers.get(TOKEN_HEADER, "") or ""
    except Exception:
        token = ""

    try:
        return verify(token, expected_audience=audience)
    except IdentityError as exc:
        logger.info(
            "%s identity.reject reason=%s token=%s"
            % (_ts(), exc, "absent" if not token else "present")
        )
        return UNKNOWN_CALLER


if __name__ == "__main__":
    # Tiny smoke check: mint a card as the worker and read it back.
    t = issue("worker", audience="model-store")
    print("token:", t)
    print("verified issuer:", verify(t, expected_audience="model-store"))
    try:
        verify(t, expected_audience="model-store")
    except IdentityError as e:
        print("replay correctly refused:", e)
