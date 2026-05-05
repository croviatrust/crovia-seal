FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Copy only what we need to install the two local packages.
COPY reference/python /app/reference/python
COPY integrations/proxy /app/integrations/proxy

RUN pip install /app/reference/python && \
    pip install /app/integrations/proxy

# The proxy uses ~/.crovia/proxy.key if no explicit key is configured.
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 7878

ENTRYPOINT ["crovia-proxy"]
