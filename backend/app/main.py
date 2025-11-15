"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .deps import get_ln_client_dep
from .logging_utils import configure_logging
from .routers import lnurl as lnurl_router
from .routers import ui as ui_router
from .macaroon_store import MacaroonNotConfiguredError

LOGGER = logging.getLogger("lnswitchboard")
BASE_DIR = Path(__file__).resolve().parents[2]
STATIC_DIR = BASE_DIR / "frontend" / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_path.parent)
    ln_client = await get_ln_client_dep()
    try:
        connection_info = await ln_client.check_connection()
        if connection_info.get("info_permission", True):
            LOGGER.info("Connected to LND at %s", settings.lnd_host)
        else:
            LOGGER.info(
                "Connected to LND at %s (macaroon missing GetInfo permission)",
                settings.lnd_host,
            )
    except MacaroonNotConfiguredError:
        LOGGER.info("Macaroon not yet configured; LND connectivity check skipped")
    except Exception as exc:  # pragma: no cover - network runtime
        LOGGER.warning("Unable to verify LND connection: %s", exc)
    yield
    await ln_client.close()


app = FastAPI(
    title="lnSwitchboard",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)

app.include_router(ui_router.router)
app.include_router(lnurl_router.router)

if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
