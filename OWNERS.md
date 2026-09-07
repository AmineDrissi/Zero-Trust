# Who owns what

Edit only your own files. If you need a change in someone else's, message them.

| Area | Owner | Files |
|---|---|---|
| ID cards / identity | Amine | `ztlib/identity.py`, `tests/` |
| Containers, both modes | Abubakar | `compose.baseline.yml`, `compose.zt.yml`, `services/`, `Makefile` |
| Permission list, logging | Ishtiaq | `policy.yaml`, `ztlib/policy.py` |
| Attack script, evidence | Sreelakshmi | `attack/`, `evidence/` |
| README, testing, diagram | Yatharth | `README.md`, `docs/` |

Branches: `abubakar/containers`, `ishtiaq/policy`, `sree/attack`, `yatharth/docs`, `amine/identity`.

Never commit to `main`. Open a pull request and set Amine as reviewer.
