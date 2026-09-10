# Build context is the repo root (see compose files) so we can pull in the
# shared ztlib/ package alongside this service's own code.
FROM python:3.12-slim
WORKDIR /app

COPY services/gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/gateway/ .
COPY ztlib ./ztlib
COPY policy.yaml

CMD ["python", "main.py"]
