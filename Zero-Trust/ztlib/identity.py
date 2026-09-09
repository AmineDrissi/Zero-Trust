"""
ztlib/identity.py
------------------
PLACEHOLDER identity layer. Amine owns the real ID-card system (signing +
verification). This file exists so gateway/worker/model-store can be built,
run, and tested end to end *before* his code lands, and so there is exactly
one place to swap in the real thing later.

get_verified_caller(request)
    Currently just reads a plain header. THIS IS INSECURE ON PURPOSE AS A
    PLACEHOLDER: any container could set this header itself and claim to be
    anyone. Ishtiaq's brief says explicitly that `caller` must come from a
    verified ID card, never a self-declared header - so this function is the
    one that must be replaced, not the services that call it.

sign_outgoing(headers, my_identity)
    Attaches "this is who I am" to an outgoing request. Amine's real version
    should attach a signed, single-use token here instead of a plain string.

TODO (coordinate with Amine, Sunday): agree on the exact header name / token
format, then update just these two functions. Nothing in gateway, worker, or
model-store should need to change.
"""

def get_verified_caller(request) -> str:
    return request.headers.get("X-ZT-Identity", "unknown")


def sign_outgoing(headers: dict, my_identity: str) -> dict:
    headers = dict(headers or {})
    headers["X-ZT-Identity"] = my_identity
    return headers
