"""PRAHARI FastAPI application."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import models  # noqa: F401 - register ORM tables
from .api import admin, anchors, auth, channels, messages, quantum, servers, sessions, users, websocket
from .config import get_settings
from .crypto import pqc
from .database import Base, close_database, get_engine, ping_database

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    engine = get_engine()
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    await ping_database()
    yield
    await close_database()


app = FastAPI(
    title="PRAHARI",
    version="1.0.0",
    description="Hybrid post-quantum end-to-end encrypted communication platform.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

for router in (
    auth.router,
    users.router,
    servers.router,
    channels.router,
    sessions.router,
    messages.router,
    anchors.router,
    quantum.router,
    admin.router,
    websocket.router,
):
    app.include_router(router)


@app.get("/", tags=["ops"])
async def root():
    return {"name": "PRAHARI", "status": "running", "docs": "/docs"}


@app.get("/health", tags=["ops"])
async def health():
    try:
        backend_name = pqc.get_backend().name
    except pqc.PQCError:
        backend_name = f"{settings.pqc_backend} (dependency unavailable)"
    return {
        "status": "ok",
        "service": "prahari-api",
        "version": app.version,
        "database": "configured",
        "pqc_algorithm": pqc.ALGORITHM,
        "pqc_backend": backend_name,
        "server_can_read_messages": False,
        "message_crypto_location": "client",
    }
