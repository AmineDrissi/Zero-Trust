FROM python:3.12-slim
WORKDIR /app

COPY services/model-store/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/model-store/ .
COPY ztlib ./ztlib
COPY policy.yaml ./policy.yaml

RUN mkdir -p /models && python -c "import os; open('/models/llama-guard.bin','wb').write(os.urandom(4*1024*1024))"

CMD ["python", "main.py"]