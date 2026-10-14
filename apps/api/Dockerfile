# syntax=docker/dockerfile:1.7
# AEGIS API / worker image. Build context: repository root (rules and scenarios are bundled).
FROM python:3.14-slim AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY apps/api/pyproject.toml apps/api/uv.lock ./
# Optional build secret "extra_ca": a CA bundle for TLS-intercepting corporate proxies.
# It is used only during these RUN steps and never stored in an image layer.
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca SSL_CERT_FILE=/run/secrets/extra_ca; fi; \
    pip install --no-cache-dir "uv>=0.11,<0.12" && uv sync --frozen --no-dev --no-install-project
COPY apps/api/src ./src
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; \
    uv sync --frozen --no-dev

FROM python:3.14-slim
RUN useradd --system --uid 10001 --home /app aegis
WORKDIR /app
COPY --from=build --chown=aegis:aegis /app /app
COPY --chown=aegis:aegis rules /srv/rules
COPY --chown=aegis:aegis simulations /srv/simulations
COPY --chown=aegis:aegis docs/knowledge /srv/docs/knowledge
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    AEGIS_RULES_DIR=/srv/rules \
    AEGIS_SCENARIOS_DIR=/srv/simulations/scenarios
USER aegis
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "aegis.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
