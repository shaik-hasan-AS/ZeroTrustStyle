FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--ssl-keyfile", "/certs/account-service/account-service.key", "--ssl-certfile", "/certs/account-service/account-service.crt", "--ssl-ca-certs", "/certs/ca/ca.crt", "--ssl-cert-reqs", "2"]
