import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

SERVICE_NAME = "gateway"
WORKER_URL = os.environ.get("WORKER_URL", "http://worker:8080")
ENFORCE_POLICY = os.environ.get("ENFORCE_POLICY", "false").lower() == "true"

if ENFORCE_POLICY:
    from ztlib.identity import sign_outgoing


@app.route("/predict", methods=["POST"])
def predict():
    body = request.get_json(silent=True) or {}

    headers = {}
    if ENFORCE_POLICY:
        headers = sign_outgoing(headers, SERVICE_NAME)

    try:
        resp = requests.post(f"{WORKER_URL}/run", json=body, headers=headers, timeout=5)
    except requests.RequestException as e:
        return jsonify(error="worker_unreachable", detail=str(e)), 502

    try:
        payload = resp.json()
    except ValueError:
        payload = {"raw": resp.text}
    return jsonify(payload), resp.status_code


@app.route("/healthz")
def health():
    return jsonify(status="ok", service=SERVICE_NAME)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
