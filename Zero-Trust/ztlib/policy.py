"""
ztlib/policy.py
----------------
STUB. Ishtiaq owns this file for real (policy.yaml + a proper evaluate()
that reads it, plus logging and the blast-radius count). This placeholder
exists purely so gateway/worker/model-store can be built and tested in
enforced mode before ishtiaq/policy is merged.

Message Ishtiaq Monday morning and confirm his real evaluate() has this
exact signature and returns this exact Decision shape - then his file can
replace this one with a straight `git checkout` and nothing else changes.

    def evaluate(caller: str, target: str, method: str, path: str) -> Decision:
        # Decision(allowed: bool, rule_id: str | None, reason: str)
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class Decision:
    allowed: bool
    rule_id: Optional[str]
    reason: str


# Deliberately narrow, hardcoded stand-in for policy.yaml. Just enough to
# prove the request path from gateway -> worker -> model-store works when
# ENFORCE_POLICY=true, and to prove an unidentified caller ("unknown") is
# refused. Ishtiaq's real evaluate() replaces this entirely.
_ALLOWED_EXACT = {
    ("gateway", "worker", "POST", "/run"),
}


def evaluate(caller: str, target: str, method: str, path: str) -> Decision:
    if (caller, target, method, path) in _ALLOWED_EXACT:
        return Decision(allowed=True, rule_id="STUB-R1", reason="stub_allow")

    if target == "model-store" and caller == "worker" and method == "GET":
        return Decision(allowed=True, rule_id="STUB-R2", reason="stub_allow")

    return Decision(allowed=False, rule_id=None, reason="no_matching_rule")
