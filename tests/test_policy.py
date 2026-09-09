"""
tests/test_policy.py — table-driven tests for ztlib/policy.evaluate().
Owner: Ishtiaq.

Run with: python -m pytest tests/test_policy.py -v
Or directly: python tests/test_policy.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ztlib.policy import evaluate, blast_radius

TEST_POLICY = {
    "default": "deny",
    "rules": [
        {"id": "R1", "from": "gateway", "to": "worker", "methods": ["POST"], "paths": ["/run"]},
        {"id": "R2", "from": "worker", "to": "model-store", "methods": ["GET"], "paths": ["/models/"]},
        {"id": "R3", "from": "worker", "to": "db", "methods": ["QUERY"], "paths": ["inference_logs:select"]},
    ],
}

# caller, target, method, path, expected_allowed, expected_rule_id
CASES = [
    # Legitimate traffic — must be allowed.
    ("gateway", "worker", "POST", "/run", True, "R1"),
    ("worker", "model-store", "GET", "/models/llama-guard.bin", True, "R2"),
    ("worker", "db", "QUERY", "inference_logs:select", True, "R3"),
    # Attacker / lateral movement — must all be denied.
    ("attacker-7f3a", "model-store", "GET", "/models/llama-guard.bin", False, None),
    ("attacker-7f3a", "db", "QUERY", "inference_logs:select", False, None),
    ("gateway", "model-store", "GET", "/models/llama-guard.bin", False, None),   # no direct gateway->model-store route
    ("worker", "worker", "POST", "/run", False, None),                          # no self-calls
    ("worker", "model-store", "DELETE", "/models/llama-guard.bin", False, None), # wrong method
    ("worker", "db", "QUERY", "users:select", False, None),                     # wrong table/path
]


def test_policy_cases():
    for caller, target, method, path, expected_allowed, expected_rule in CASES:
        d = evaluate(caller, target, method, path, policy=TEST_POLICY)
        assert d.allowed == expected_allowed, (
            f"{caller}->{target} {method} {path}: "
            f"expected allowed={expected_allowed}, got {d.allowed}"
        )
        if expected_allowed:
            assert d.rule_id == expected_rule


def test_blast_radius():
    baseline, zt = blast_radius(policy=TEST_POLICY, service_count=4)
    assert baseline == 12  # 4 services, every directed pair, flat network
    assert zt == 3         # R1, R2, R3


def test_deleting_a_rule_shrinks_reachability():
    """Proves policy.yaml is really the source of truth: remove a rule,
    reachability drops, with zero code changes."""
    smaller_policy = {
        "default": "deny",
        "rules": TEST_POLICY["rules"][:2],  # drop R3
    }
    d = evaluate("worker", "db", "QUERY", "inference_logs:select", policy=smaller_policy)
    assert d.allowed is False
    _, zt = blast_radius(policy=smaller_policy, service_count=4)
    assert zt == 2


if __name__ == "__main__":
    test_policy_cases()
    test_blast_radius()
    test_deleting_a_rule_shrinks_reachability()
    print("all policy test cases passed")