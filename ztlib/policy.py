"""
ztlib/policy.py — Zero Trust policy evaluator.
Owner: Ishtiaq. Single source of truth for permissions is policy.yaml.

Deny unless a rule says allow. Never allow unless a rule says deny.

`caller` must be the verified name returned by ztlib.identity.verify() —
never a value the caller announces about itself in a header. If a
container can just say "I am the worker" and be believed, this whole
project is pointless.
"""

from __future__ import annotations

import logging
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

POLICY_FILE = Path(__file__).resolve().parent.parent / "policy.yaml"

logger = logging.getLogger("ztlib.policy")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stdout)
    _handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule_id: Optional[str]
    reason: str


_cached_policy: Optional[dict] = None


def _load_policy(path: Path = POLICY_FILE) -> dict:
    global _cached_policy
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    # Fail closed even if someone edits this file badly.
    if data.get("default") != "deny":
        data["default"] = "deny"
    _cached_policy = data
    return data


def _path_matches(rule_path: str, request_path: str) -> bool:
    """Prefix match if the rule path ends in '/', exact match otherwise."""
    if rule_path.endswith("/"):
        return request_path.startswith(rule_path)
    return rule_path == request_path


def evaluate(
    caller: str,
    target: str,
    method: str,
    path: str,
    policy: Optional[dict] = None,
) -> Decision:
    """
    Returns Decision(allowed, rule_id, reason).

    If no rule in policy.yaml matches: allowed=False, rule_id=None,
    reason="no_matching_rule".

    caller must be the verified name returned by ztlib.identity.verify() —
    NOT a self-declared header value.
    """
    policy = policy if policy is not None else (_cached_policy or _load_policy())

    for rule in policy.get("rules", []):
        if rule.get("from") != caller:
            continue
        if rule.get("to") != target:
            continue
        if method not in rule.get("methods", []):
            continue
        if not any(_path_matches(p, path) for p in rule.get("paths", [])):
            continue
        return Decision(allowed=True, rule_id=rule["id"], reason="matched_rule")

    return Decision(allowed=False, rule_id=None, reason="no_matching_rule")


def log_decision(
    caller: str,
    target: str,
    method: str,
    path: str,
    decision: Decision,
    *,
    identity: str = "none",
    token: str = "absent",
    hop: int = 1,
    latency_ms: float = 0.0,
    target_port: int = 8080,
) -> str:
    """
    Emit one structured log line per access decision — allow AND deny.
    A log that only ever shows refusals doesn't prove normal traffic
    still flows, which is half the argument.
    """
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    verdict = "policy.allow" if decision.allowed else "policy.deny"
    status = 200 if decision.allowed else 403
    matched = decision.rule_id if decision.rule_id else "<none>"

    line = (
        f"{ts} {verdict} src={caller} dst={target}:{target_port} "
        f"route={method} {path} identity={identity} token={token} "
        f"matched_rule={matched} default=deny decision={status} "
        f"hop={hop} latency={latency_ms:.1f}ms"
    )
    logger.info(line)
    return line


def blast_radius(policy: Optional[dict] = None, service_count: int = 4) -> tuple[int, int]:
    """
    baseline    = every service can reach every other service (flat network).
    zero_trust  = only the distinct (from, to) pairs explicitly allowed.
    Returns (baseline_paths, zero_trust_paths).
    """
    policy = policy if policy is not None else (_cached_policy or _load_policy())
    baseline = service_count * (service_count - 1)
    pairs = {(r["from"], r["to"]) for r in policy.get("rules", [])}
    return baseline, len(pairs)


def print_blast_radius(service_count: int = 4) -> None:
    baseline, zt = blast_radius(service_count=service_count)
    print(f"blast_radius: baseline={baseline} paths zero_trust={zt} paths")


if __name__ == "__main__":
    print_blast_radius()