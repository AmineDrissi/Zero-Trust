FROM python:3.12-slim
WORKDIR /app

COPY services/model-store/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/model-store/ .
COPY ztlib ./ztlib
COPY policy.yaml

# Never commit a real model file (GitHub rejects >100MB anyway). This fake
# 4MB blob of random bytes fingerprints exactly like a real one, which is
# all the attack needs to prove theft via a SHA-256 match.
RUN mkdir -p /models && python -c "import os; open('/models/llama-guard.bin','wb').write(os.urandom(4*1024*1024))"

CMD ["python", "main.py"]
