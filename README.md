# Zero Trust Access Demo for AI Inference Clusters

**GISEC 2026 — School of Cyber Defense, Stage 2 · Team Curtin (Curtin University Dubai)**

A small AI inference cluster, built twice. On a flat network a compromised container steals
the model file and reads the database. With per-request identity and a deny-by-default
allow-list, **the identical attack script** is refused at its first move and the refusal is
logged. Same bytes, opposite outcome.

---

## Requirements

- **Docker Desktop** (or Docker Engine) with Compose v2 — `docker compose version` must work
- ~2 GB free disk, and internet for the first build (to pull `python:3.12-slim` and `postgres:16`)
- Optional: `make`. Every command below is also given as raw `docker compose` for machines without it.

Nothing else. No Python packages to install on the host, no cloud account, no model download.

---

## Quick start

```bash
git clone https://github.com/AmineDrissi/Zero-Trust.git
cd Zero-Trust
make demo
```

No `make` (e.g. stock Windows)? Run the four commands it wraps:

```bash
docker compose -f compose.baseline.yml up -d --build --wait
docker compose -f compose.baseline.yml run --rm attacker
docker compose -f compose.baseline.yml down -v

docker compose -f compose.zt.yml up -d --build --wait
docker compose -f compose.zt.yml run --rm attacker
docker compose -f compose.zt.yml down -v
```

First run takes a few minutes while images build. Later runs are seconds.

---

## What you should see

**Mode A — flat network.** The attack succeeds on all three hops:

```
[HOP 1] model-store  GET /models/llama-guard.bin  -> 200 OK  STOLEN  sha256=3671e344... (4.0 MB)
[HOP 2] postgres     SELECT inference_logs        -> 5 rows  LEAKED
[HOP 3] worker       POST /run                    -> 200 OK  REACHED

hops_attempted=3  hops_succeeded=3
```

**Mode B — zero trust.** The same script, unchanged, is refused everywhere:

```
[HOP 1] model-store  GET /models/llama-guard.bin  -> 403 DENIED  rule=<none> reason=no_matching_rule
[HOP 2] postgres     SELECT inference_logs        -> BLOCKED  no route to host
[HOP 3] worker       POST /run                    -> 403 DENIED  rule=<none> reason=no_matching_rule

hops_attempted=3  hops_succeeded=0
```

The SHA-256 printed in Mode A is the real hash of the model file the store holds — proof the
model actually left the service, not just that a request returned 200.

Captured output from a full run is committed in [`evidence/`](evidence/).

---

## Running one mode at a time

| Command | Without `make` |
|---|---|
| `make baseline` | `docker compose -f compose.baseline.yml up -d --build --wait` then `run --rm attacker` |
| `make zt` | `docker compose -f compose.zt.yml up -d --build --wait` then `run --rm attacker` |
| `make demo` | both, back to back |
| `make clean` | `docker compose -f compose.baseline.yml down -v` and the same for `compose.zt.yml` |

The legitimate path keeps working in **both** modes — the control stops the attacker without
breaking normal traffic. With a stack up, check it:

```bash
curl -X POST http://localhost:8000/predict -H "Content-Type: application/json" -d "{\"prompt\":\"is this spam?\"}"
```

Port 8000 taken? Set `GATEWAY_PORT` (e.g. `GATEWAY_PORT=8900 make baseline`).

---

## How it works

Five services: `gateway` → `worker` → `model-store`, a `postgres` database, and an `attacker`
container that plays a workload the attacker already controls.

Both modes run **the same images and the same attack file**. Only two things change:

1. **`ENFORCE_POLICY`** — off in Mode A, on in Mode B.
2. **The networks** — one flat network in Mode A; in Mode B, split so only permitted pairs share one.

When enforcement is on, every service-to-service call carries a signed ID card:

| Claim | Meaning |
|---|---|
| `iss` | who is calling — verified, never self-declared |
| `aud` | who the token is for |
| `exp` | 30 seconds |
| `jti` | one-time value; a replay is refused |

The receiver verifies the signature *before* trusting any claim, then asks
[`policy.yaml`](policy.yaml) whether that caller may make that call. Anything not explicitly
allowed is denied and logged.

**The attacker is deliberately left on the model-store and worker networks in Mode B.** It can
reach them at the network layer; what stops it is the identity check inside the service. That is
the point — segmentation alone is not the control. Only the database hop is stopped by network
isolation, because raw Postgres has no application-level policy hook here.

---

## Repository layout

```
compose.baseline.yml   Mode A — one flat network, no checks
compose.zt.yml         Mode B — segmented networks, enforcement on
policy.yaml            the allow-list; the single source of truth for permissions
ztlib/identity.py      signed, single-use ID cards (issue / verify / replay cache)
ztlib/policy.py        deny-by-default evaluator + structured decision logging
services/gateway/      POST /predict — the front door
services/worker/       POST /run — fetches the model, returns a prediction
services/model-store/  GET /models/<name> — holds the model; generates a 4 MB fake at build
services/db/init.sql   seeds the inference_logs table
attack/attack.py       the three-hop attack — identical in both modes
evidence/              captured output from a real run
tests/                 identity and policy test suites
```

---

## Tests

No pytest or third-party packages needed:

```bash
python tests/test_identity.py
python tests/test_policy.py
```

`test_identity.py` covers the refusals that matter: forged signature, wrong audience, expired
token, **replayed `jti`**, and the `alg=none` downgrade. `test_policy.py` is table-driven over
legitimate calls and every lateral move.

Blast radius, straight from the policy file:

```bash
python ztlib/policy.py
# blast_radius: baseline=12 paths zero_trust=3 paths
```

---

## Troubleshooting

**`docker compose` not found** — you have Compose v1. Use `docker-compose` or upgrade Docker Desktop.

**Port 8000 already allocated** — set `GATEWAY_PORT` to something free.

**Windows: `make` is not recognised** — use the raw `docker compose` commands above, or run from WSL.

**Windows: Docker Desktop won't start, stale `.sock` file** — a pending Windows restart usually
causes this. Reboot, then start Docker Desktop before running the demo.

**Second run misbehaves** — `make clean` (or `down -v` on both files) removes the volumes and
gives you a cold start.

**`ModuleNotFoundError: yaml` inside a service** — the image is stale. Rebuild with `--build`;
`pyyaml` is pinned in each service's `requirements.txt`.

---

## Known limitations

Stated plainly, because they are the honest boundary of a five-day prototype:

- **Symmetric keys.** Service keys derive from one shared seed, so a fully compromised service
  could mint a token for another. Production issues asymmetric per-workload identities
  (SPIFFE/SPIRE X.509 SVIDs). The token format is built to swap.
- **In-process replay cache.** The single-use check lives in one process, so it is per-container.
  Multiple replicas would share it via Redis.
- **The database hop is stopped by network isolation, not an app-layer check.** A production
  design fronts data stores with an identity-aware proxy.
- **Scope.** This demonstrates one control well. It is not a complete zero-trust architecture —
  no device posture, no continuous re-evaluation, no secrets rotation.
