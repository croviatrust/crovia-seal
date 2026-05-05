FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY reference/python /app/reference/python
COPY integrations/tlog /app/integrations/tlog

RUN pip install /app/reference/python && \
    pip install /app/integrations/tlog

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 7979

ENTRYPOINT ["crovia-tlog"]
