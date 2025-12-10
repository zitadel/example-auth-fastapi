"""Flask application factory for ZITADEL PKCE authentication demo."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from lib.auth import register_auth_routes
from lib.config import config
from lib.guard import redirect_exception_handler, RedirectException
from app.routes.root import router as root_router


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app() -> FastAPI:
    app = FastAPI()

    app.state.templates = templates

    app.add_middleware(
        SessionMiddleware,
        secret_key=config.SESSION_SECRET,
        same_site="lax",
        https_only=config.PY_ENV == "production",
        max_age=config.SESSION_DURATION,
    )

    static_dir = BASE_DIR / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
        if exc.status_code == 404:
            return templates.TemplateResponse(
                "not-found.html",
                {"request": request, "url_for": request.url_for},
                status_code=404,
            )
        raise exc

    app.add_exception_handler(RedirectException, redirect_exception_handler)

    app.include_router(root_router)
    register_auth_routes(app, templates)

    return app


app = create_app()
