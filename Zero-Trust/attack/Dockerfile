FROM python:3.12-slim
WORKDIR /app

COPY attack/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY attack/attack.py .

CMD ["python", "attack.py"]
