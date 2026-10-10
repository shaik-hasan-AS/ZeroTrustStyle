FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--ssl-keyfile", "/certs/gateway/gateway.key", "--ssl-certfile", "/certs/gateway/gateway.crt", "--ssl-ca-certs", "/certs/ca/ca.crt", "--ssl-cert-reqs", "2"]
