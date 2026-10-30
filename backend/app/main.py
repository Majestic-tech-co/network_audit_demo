"""
NetAudit API — FastAPI application entry point.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
import structlog

from app.core.config import settings
from app.core.limiter import limiter
from app.core.logging import configure_logging
from app.db.session import check_schema

# Route modules
from app.api.routes import auth, scans, findings, devices, dashboard, settings as settings_routes, agent, user, users, schedules, reports, topology as topology_routes
from app.api.routes import ws as ws_routes
from app.api.routes.capture import router as capture_router, ws_router as capture_ws_router
from app.api.routes.agent_download import router as agent_download_router
from app.core.websocket import ws_manager
import app.tasks.capture_tasks  # noqa: F401

configure_logging()
log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("netaudit_starting", environment=settings.ENVIRONMENT)
    await check_schema()
    await ws_manager.startup()
    log.info("database_ready")
    yield
    await ws_manager.shutdown()
    log.info("netaudit_shutting_down")


app = FastAPI(
    title="NetAudit API",
    description="AI-powered network audit platform",
    version="1.0.0",
    lifespan=lifespan,
    # Disable docs in production
    docs_url="/api/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/api/redoc" if settings.ENVIRONMENT != "production" else None,
)

# ─── Rate limiting ────────────────────────────────────────────────

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ─── Middleware ────────────────────────────────────────────────────

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Turnstile-Token"],
)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Defense in depth: API responses are never cached and never framed/sniffed."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    if not request.url.path.startswith(("/api/docs", "/api/redoc")):  # dev-only Swagger UI needs scripts
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    return response


# ─── Error handlers ───────────────────────────────────────────────
# Responses never contain stack traces, SQL/driver messages or echoed request values
# (FastAPI's default 422 body includes the submitted "input", e.g. passwords).

@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    errors = [
        {"loc": [str(p) for p in e.get("loc", [])], "msg": e.get("msg", "Invalid value")}
        for e in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    log.error("unhandled_exception", path=request.url.path, error_type=type(exc).__name__, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Something went wrong. Please try again later."})


# ─── Routes ───────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(devices.router)
app.include_router(dashboard.router)
app.include_router(settings_routes.router)
app.include_router(agent.router)
app.include_router(user.router)
app.include_router(users.router)
app.include_router(schedules.router)
app.include_router(reports.router)
app.include_router(ws_routes.router)
app.include_router(topology_routes.router)
app.include_router(capture_router)
app.include_router(capture_ws_router)
app.include_router(agent_download_router)


# ─── Health check ─────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


# ─── 404 catch-all (for SPA routing) ──────────────────────────────
# Nginx handles this in production, but useful for dev

@app.get("/api/{path:path}", include_in_schema=False)
async def api_404(path: str):
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Not found")
