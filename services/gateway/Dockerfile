FROM python:3.12-slim
WORKDIR /app

COPY services/gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/gateway/ .
COPY ztlib ./ztlib
COPY policy.yaml ./policy.yaml

CMD ["python", "main.py"]