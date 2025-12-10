"""FastAPI application factory for ZITADEL PKCE authentication demo.

This module creates and configures the FastAPI application with all necessary
middleware, exception handlers, and routes for OAuth 2.0 authentication with
ZITADEL using the PKCE flow.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.routes.root import router as root_router
from lib.auth import register_auth_routes
from lib.config import config
from lib.guard import RedirectError, redirect_exception_handler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Initializes the application with:
    - Session middleware for secure cookie-based sessions
    - Static file serving
    - Custom exception handlers for 404 and authentication redirects
    - Authentication routes
    - Application routes

    Returns:
        FastAPI: Configured application instance ready to run
    """
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
        """Handle HTTP exceptions with custom error pages.

        Args:
            request: The incoming HTTP request
            exc: The HTTP exception that was raised

        Returns:
            Response: Custom 404 page or re-raises other exceptions
        """
        if exc.status_code == 404:
            return templates.TemplateResponse(
                request=request,
                name="not-found.html",
                context={"url_for": request.url_for},
                status_code=404,
            )
        raise exc

    app.add_exception_handler(RedirectError, redirect_exception_handler)

    app.include_router(root_router)
    register_auth_routes(app, templates)

    logger.info("FastAPI application initialized")

    return app


app = create_app()
