"""The attack. One script, unchanged, run in both modes.

Sreelakshmi owns this file.

If this file differs between the two runs it stops being evidence.
Same bytes, same commands, different outcome.

    HOP 1  steal the model   GET model-store:8080/models/llama-guard.bin
    HOP 2  read the database SELECT * FROM inference_logs LIMIT 5
    HOP 3  reach a peer      POST worker:8080/run

Print one line per hop, then: hops_attempted=3 hops_succeeded=N
Prove the theft with the SHA-256 of the retrieved file, not a status code.
"""


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
