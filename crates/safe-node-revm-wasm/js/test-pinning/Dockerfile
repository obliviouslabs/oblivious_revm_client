FROM python:3.13-alpine

WORKDIR /app
COPY mock_tls_rpc.py .

EXPOSE 8443
ENTRYPOINT ["python", "/app/mock_tls_rpc.py"]
