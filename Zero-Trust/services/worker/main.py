import os
import hashlib
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

SERVICE_NAME = "worker"
MODEL_STORE_URL = os.environ.get("MODEL_STORE_URL", "http://model-store:8080")
MODEL_NAME = "llama-guard.bin"
ENFORCE_POLICY = os.environ.get("ENFORCE_POLICY", "false").lower() == "true"

if ENFORCE_POLICY:
    from ztlib.policy import evaluate
    from ztlib.identity import get_verified_caller, sign_outgoing


@app.route("/run", methods=["POST"])
def run():
    if ENFORCE_POLICY:
        caller = get_verified_caller(request)
        decision = evaluate(caller, SERVICE_NAME, "POST", "/run")
        if not decision.allowed:
            return jsonify(
                error="forbidden",
                reason=decision.reason,
                rule=decision.rule_id,
            ), 403

    headers = {}
    if ENFORCE_POLICY:
        headers = sign_outgoing(headers, SERVICE_NAME)

    try:
        resp = requests.get(f"{MODEL_STORE_URL}/models/{MODEL_NAME}", headers=headers, timeout=5)
    except requests.RequestException as e:
        return jsonify(error="model_store_unreachable", detail=str(e)), 502

    if resp.status_code != 200:
        return jsonify(error="model_unavailable", upstream_status=resp.status_code), 502

    digest = hashlib.sha256(resp.content).hexdigest()
    body = request.get_json(silent=True) or {}

    return jsonify(
        prediction="fake-positive",
        model=MODEL_NAME,
        model_sha256=digest,
        input_echo=body,
    )


@app.route("/healthz")
def health():
    return jsonify(status="ok", service=SERVICE_NAME)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
