# Inference endpoint image. Build context = a folder containing serving/ and src/federated_ids/
# (scripts/azure/deploy.sh assembles it). The model bundle and TLS files are mounted at runtime,
# not baked into the image.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch==2.14.1 \
 && pip install numpy==2.5.3 fastapi==0.138.2 uvicorn==0.49.0 pydantic==2.14.1

WORKDIR /app
COPY src/federated_ids /app/federated_ids
COPY serving /app/serving
ENV PYTHONPATH=/app MODEL_DIR=/model

RUN useradd --create-home --uid 10001 ids
USER ids
EXPOSE 8443
# API_KEY must be supplied at run time (docker run -e API_KEY=...); TLS cert/key mounted at /tls
CMD ["uvicorn", "serving.app:app", "--host", "0.0.0.0", "--port", "8443", \
     "--ssl-certfile", "/tls/cert.pem", "--ssl-keyfile", "/tls/key.pem"]
