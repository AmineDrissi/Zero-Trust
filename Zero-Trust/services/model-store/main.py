import os
from flask import Flask, request, jsonify, send_from_directory, abort

app = Flask(__name__)

SERVICE_NAME = "model-store"
MODELS_DIR = "/models"
ENFORCE_POLICY = os.environ.get("ENFORCE_POLICY", "false").lower() == "true"

if ENFORCE_POLICY:
    from ztlib.policy import evaluate
    from ztlib.identity import get_verified_caller


@app.route("/models/<path:name>", methods=["GET"])
def get_model(name):
    if ENFORCE_POLICY:
        caller = get_verified_caller(request)
        decision = evaluate(caller, SERVICE_NAME, "GET", f"/models/{name}")
        if not decision.allowed:
            return jsonify(
                error="forbidden",
                reason=decision.reason,
                rule=decision.rule_id,
            ), 403

    full_path = os.path.join(MODELS_DIR, name)
    if not os.path.isfile(full_path):
        abort(404)
    return send_from_directory(MODELS_DIR, name)


@app.route("/healthz")
def health():
    return jsonify(status="ok", service=SERVICE_NAME)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
