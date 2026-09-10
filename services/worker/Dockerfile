FROM python:3.12-slim
WORKDIR /app

COPY services/worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/worker/ .
COPY ztlib ./ztlib
COPY policy.yaml ./policy.yaml

CMD ["python", "main.py"]