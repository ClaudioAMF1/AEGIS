"""ASGI application factory."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from aegis import __version__
from aegis.config import get_settings
from aegis.db import get_engine, session_factory
from aegis.detection.registry import registry
from aegis.observability import configure_logging, metrics
from aegis.realtime import hub
from aegis.routers import (
    admin,
    alerts,
    analytics,
    auth,
    demo,
    detections,
    endpoints,
    events,
    incidents,
    ingest,
)

log = logging.getLogger("aegis.http")

API_PREFIX = "/api/v1"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    db = session_factory()()
    try:
        stats = registry.bootstrap(db)
        log.info("rules loaded", extra={"path": str(stats)})
    finally:
        db.close()
    await hub.start()
    yield
    await hub.stop()


def create_app() -> FastAPI:
    settings = get_settings()
    if settings.environment.value != "test":
        configure_logging()
    app = FastAPI(
        title="AEGIS API",
        version=__version__,
        description="Autonomous Cyber Defense Platform — telemetry ingestion, detection and "
        "investigation API.",
        lifespan=lifespan,
        docs_url=f"{API_PREFIX}/docs",
        openapi_url=f"{API_PREFIX}/openapi.json",
        redoc_url=None,
    )
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["content-type", "x-csrf-token", "authorization"],
        )

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception(
                "unhandled error", extra={"request_id": request_id, "path": request.url.path}
            )
            response = JSONResponse(
                {"detail": "internal server error", "request_id": request_id}, status_code=500
            )
        duration = time.perf_counter() - started
        route = request.scope.get("route")
        route_path = getattr(route, "path", "unmatched")
        metrics.HTTP_REQUESTS.labels(request.method, route_path, str(response.status_code)).inc()
        metrics.HTTP_LATENCY.labels(route_path).observe(duration)
        response.headers["x-request-id"] = request_id
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["referrer-policy"] = "no-referrer"
        response.headers["cache-control"] = "no-store"
        if route_path != "unmatched" and not route_path.endswith("/metrics"):
            log.info(
                "request",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": route_path,
                    "status": response.status_code,
                    "duration_ms": round(duration * 1000, 2),
                },
            )
        return response

    for module in (
        auth,
        ingest,
        endpoints,
        events,
        detections,
        alerts,
        incidents,
        analytics,
        admin,
        demo,
    ):
        app.include_router(module.router, prefix=API_PREFIX)

    @app.get(f"{API_PREFIX}/health", tags=["ops"])
    def health() -> dict[str, object]:
        checks: dict[str, str] = {}
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception:
            checks["database"] = "error"
        if settings.redis_url:
            try:
                import redis

                redis.Redis.from_url(settings.redis_url, socket_timeout=1).ping()
                checks["redis"] = "ok"
            except Exception:
                checks["redis"] = "error"
        status_ = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
        return {
            "status": status_,
            "version": __version__,
            "checks": checks,
            "pipeline_mode": settings.pipeline_mode.value,
            "environment": settings.environment.value,
        }

    @app.get("/metrics", include_in_schema=False)
    def prometheus() -> PlainTextResponse:
        return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)

    return app
