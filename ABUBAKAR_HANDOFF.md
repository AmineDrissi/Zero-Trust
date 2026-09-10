# Abubakar's part — handoff notes

Everything below is built, tested, and working (tested by running all three
services directly with plain `python3`, hitting them with `curl` in both
enforced and unenforced mode — Docker wasn't available in the environment
this was drafted in, so **your first job Sunday is `make clean && make demo`
on your own machine** to confirm it also works through Docker end to end).

## What's here

```
compose.baseline.yml   Mode A — flat network, ENFORCE_POLICY=false everywhere
compose.zt.yml         Mode B — segmented networks, ENFORCE_POLICY=true
Makefile               baseline / zt / demo / clean
services/gateway/      POST /predict -> forwards to worker
services/worker/       POST /run -> fetches model, returns fake prediction
services/model-store/  GET /models/<name>, generates the fake 4MB model at build
services/db/init.sql   seeds inference_logs table
attack/                a placeholder attacker (see below)
ztlib/                 identity.py + policy.py stubs (see below)
```

Both compose files use the **same service images**, controlled by one env
var, `ENFORCE_POLICY`. Mode A sets it false everywhere (no checks at all,
by design). Mode B sets it true, and splits the services onto three
networks so only allowed pairs share a network:

- `net_gw_worker` — gateway, worker
- `net_worker_store` — worker, model-store
- `net_worker_db` — worker, db

**The attacker is deliberately placed on `net_worker_store` and
`net_gw_worker`** in Mode B — it can reach model-store and worker at the
network layer. What stops it there is the identity/policy check inside
those services, which is the actual point of zero trust. It's deliberately
**not** on `net_worker_db`, so the database hop fails at the network layer
instead — raw Postgres has no app-level policy hook in this prototype, so
that hop is network-isolation only.

## Two stubs you need to know about — coordinate this week

### 1. `ztlib/policy.py` — Ishtiaq owns this for real

Right now it's a hardcoded placeholder that only allows
`gateway->worker->model-store`, so the happy path works and an unknown
caller gets refused. **Message Ishtiaq Monday morning** and confirm his
real `evaluate()` has exactly this signature:

```python
def evaluate(caller: str, target: str, method: str, path: str) -> Decision:
    # Decision(allowed: bool, rule_id: str | None, reason: str)
```

If it matches, he can `git checkout` his `ztlib/policy.py` over this stub
and nothing else in gateway/worker/model-store needs to change.

### 2. `ztlib/identity.py` — Amine owns this for real

This is currently a **placeholder that just reads a plain header**
(`X-ZT-Identity`). I tested this on purpose: a request that spoofs that
header (`curl -H "X-ZT-Identity: gateway" ...` straight at the worker)
currently gets through in "enforced" mode. That's expected and it's
exactly the bug Ishtiaq's brief warns about — caller identity must come
from a *verified* ID card, not a self-declared header. Until Amine's real
signing/verification lands, **Mode B is not actually secure**, only
structurally ready for it. Message Amine Sunday about the exact
header/token format so you two agree before he starts.

## Placeholder attacker

`attack/attack.py` is a full working 3-hop script (steal model, read db,
reach worker) that already matches Sreelakshmi's expected output format
byte-for-byte, including the SHA-256 proof. It's there so you're not
blocked waiting for her real one — you can already run `make demo` and see
a real before/after. She owns `attack/attack.py` for real (the stolen-token
replay hop, capturing evidence into `evidence/`) and will replace this file
outright.

## Known things to double check on your machine

- **Port 8000 in use**: change it via `GATEWAY_PORT=8001 make demo`, no
  compose file edits needed — it's already parameterized.
- **Apple Silicon**: every build service already has
  `platform: linux/amd64` set.
- **Project name collisions**: both compose files set a `name:` field
  (`zt-baseline` / `zt-zerotrust`) so Docker keeps their resources apart.
- **Cold start / second run**: `make demo` uses `--wait` on healthchecks
  (not a fixed `sleep`), and `down -v` after each mode, so `make clean &&
  make demo` and running `make demo` twice in a row should both just work.
  This is exactly what Yatharth will stress-test Wednesday — worth running
  it yourself twice before Monday's checkpoint.
