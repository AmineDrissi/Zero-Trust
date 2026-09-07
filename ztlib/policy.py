"""Allow-list evaluation. Deny by default.

Ishtiaq owns this file.

    evaluate(caller, target, method, path) -> Decision(allowed, rule_id, reason)

If no rule in policy.yaml matches: allowed=False, rule_id=None,
reason="no_matching_rule".

`caller` must be the verified name returned by ztlib.identity.verify().
"""

from dataclasses import dataclass


@dataclass
class Decision:
    allowed: bool
    rule_id: str | None
    reason: str


def evaluate(caller: str, target: str, method: str, path: str) -> Decision:
    raise NotImplementedError
