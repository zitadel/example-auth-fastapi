"""Flask application factory for ZITADEL PKCE authentication demo."""

from __future__ import annotations

import json
import logging
from typing import Any

from flask import Flask, g, render_template, url_for

from lib.auth import register_auth_routes
from lib.config import config
from lib.guard import require_auth

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__, template_folder="../templates", static_folder="../static")

    app.secret_key = config.SESSION_SECRET
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = config.PY_ENV == "production"
    app.config["PERMANENT_SESSION_LIFETIME"] = config.SESSION_DURATION

    logger.info("Flask application initialized")

    register_auth_routes(app)

    @app.route("/")
    def home() -> str:
        """Render the home page with authentication status."""
        session_data = g.get("auth_session")
        return render_template(
            "index.html",
            isAuthenticated=bool(session_data),
            loginUrl=url_for("auth.signin_zitadel"),
        )

    @app.route("/profile")
    @require_auth
    def profile() -> str:
        """Display authenticated user's profile information."""
        session_data = g.auth_session
        user_json = json.dumps(session_data.get("user", {}), indent=2)
        return render_template("profile.html", userJson=user_json)

    @app.errorhandler(404)
    def not_found(error: Any) -> tuple[str, int]:
        """Handle 404 Not Found errors."""
        return render_template("not-found.html"), 404

    return app
