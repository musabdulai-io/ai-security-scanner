# backend/app/main.py
"""FastAPI application entry point for AI Security Scanner."""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.core import AppException, logs, settings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan handler with background cleanup task."""
    from backend.app.features.scanner.routes import cleanup_old_scans

    logs.info("Starting application", "main", {"version": settings.APP_VERSION})

    # Start background cleanup task
    cleanup_task = asyncio.create_task(cleanup_old_scans())
    logs.info("Started scan cleanup background task", "main")

    yield

    # Cancel cleanup task on shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    logs.info("Application shutdown complete", "main")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Security scanner for LLM/RAG applications",
    lifespan=lifespan,
)

# CORS middleware
origins = [
    origin.strip()
    for origin in settings.ALLOWED_ORIGINS.split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(AppException)
async def app_exception_handler(request: Request, exc: AppException) -> JSONResponse:
    """Handle application exceptions."""
    logs.error(
        exc.message,
        "exception",
        metadata={"status_code": exc.status_code, **exc.details},
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.message,
            "details": exc.details,
        },
    )


@app.get("/healthcheck")
async def healthcheck() -> dict:
    """Simple healthcheck for Cloud Run startup probe."""
    return {"status": "ok"}


@app.get("/health")
async def health_check() -> dict:
    """Detailed health check endpoint."""
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/")
async def root() -> dict:
    """Root endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
    }


# Import and include routers
from backend.app.features.scanner.routes import router as scanner_router

app.include_router(scanner_router, prefix=settings.API_PREFIX)
