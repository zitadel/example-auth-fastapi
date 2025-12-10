"""ZITADEL authentication routes using Authlib Flask integration."""

from __future__ import annotations

import logging
import secrets
from typing import Any
from urllib.parse import urlencode

from authlib.integrations.flask_client import OAuth
from flask import Blueprint, Flask, redirect, render_template, request, session, url_for

from lib.config import config
from lib.guard import require_auth
from lib.message import get_message
from lib.scopes import ZITADEL_SCOPES

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

oauth = OAuth()


def get_well_known_url(domain: str) -> str:
    return f"{domain}/.well-known/openid-configuration"


def init_oauth(app: Flask) -> None:
    """Initialize OAuth client with Flask app context."""
    oauth.init_app(app)
    oauth.register(
        name="zitadel",
        client_id=config.ZITADEL_CLIENT_ID,
        client_secret=config.ZITADEL_CLIENT_SECRET,
        server_metadata_url=get_well_known_url(config.ZITADEL_DOMAIN),
        client_kwargs={
            "scope": ZITADEL_SCOPES,
            "code_challenge_method": "S256",
        },
    )


@auth_bp.route("/csrf")
def csrf() -> dict[str, str]:
    """Generate CSRF token for form submissions."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrfToken": session["csrf_token"]}


@auth_bp.route("/signin")
def signin() -> str:
    """Render the sign-in page."""
    error = request.args.get("error")
    providers = [
        {
            "id": "zitadel",
            "name": "ZITADEL",
            "signinUrl": url_for("auth.signin_zitadel"),
        }
    ]
    return render_template(
        "auth/signin.html",
        providers=providers,
        callbackUrl=request.args.get("callbackUrl") or config.ZITADEL_POST_LOGIN_URL,
        message=get_message(error, "signin-error") if error else None,
    )


@auth_bp.route("/signin/zitadel", methods=["POST"])
def signin_zitadel() -> Any:
    """Initiate OAuth 2.0 authorization flow with PKCE."""
    csrf_token = request.form.get("csrfToken")
    stored_token = session.get("csrf_token")

    if not csrf_token or not stored_token or not secrets.compare_digest(csrf_token, stored_token):
        logger.warning("CSRF token validation failed")
        return redirect(url_for("auth.signin", error="verification"))

    session.pop("csrf_token", None)
    session["post_login_url"] = request.form.get("callbackUrl", config.ZITADEL_POST_LOGIN_URL)

    redirect_uri = config.ZITADEL_CALLBACK_URL
    logger.info("Initiating OAuth authorization flow")
    return oauth.zitadel.authorize_redirect(redirect_uri)


@auth_bp.route("/callback")
def callback() -> Any:
    """Handle OAuth 2.0 callback from ZITADEL."""
    try:
        token = oauth.zitadel.authorize_access_token()

        userinfo = oauth.zitadel.userinfo()

        old_session_data = dict(session)
        session.clear()
        for key, value in old_session_data.items():
            if key in ("post_login_url",):
                session[key] = value

        session["auth_session"] = {
            "user": userinfo,
            "access_token": token.get("access_token"),
            "id_token": token.get("id_token"),
            "refresh_token": token.get("refresh_token"),
            "expires_at": token.get("expires_at"),
        }

        post_login_url = session.pop("post_login_url", config.ZITADEL_POST_LOGIN_URL)
        logger.info(f"Authentication successful for user: {userinfo.get('sub')}")
        return redirect(post_login_url)

    except Exception as e:
        logger.exception("Token exchange failed: %s", str(e))
        return redirect(url_for("auth.error_page", error="callback"))


@auth_bp.route("/logout", methods=["POST"])
def logout() -> Any:
    """Initiate logout flow with ZITADEL."""
    try:
        logout_state = secrets.token_urlsafe(32)
        session["logout_state"] = logout_state

        metadata = oauth.zitadel.load_server_metadata()
        end_session_endpoint = metadata.get("end_session_endpoint")

        if end_session_endpoint:
            params = {
                "post_logout_redirect_uri": config.ZITADEL_POST_LOGOUT_URL,
                "client_id": config.ZITADEL_CLIENT_ID,
                "state": logout_state,
            }
            logout_url = f"{end_session_endpoint}?{urlencode(params)}"
            logger.info("Initiating logout flow")
            return redirect(logout_url)

        session.clear()
        return redirect(config.ZITADEL_POST_LOGOUT_URL)

    except Exception as e:
        logger.exception("Logout initiation failed: %s", str(e))
        session.clear()
        return redirect(config.ZITADEL_POST_LOGOUT_URL)


@auth_bp.route("/logout/callback")
def logout_callback() -> Any:
    """Handle logout callback from ZITADEL with state validation."""
    received_state = request.args.get("state")
    stored_state = session.get("logout_state")

    if received_state and stored_state and secrets.compare_digest(received_state, stored_state):
        session.clear()
        logger.info("Logout successful")
        return redirect(url_for("auth.logout_success"))

    logger.warning("Logout state validation failed")
    reason = "Invalid or missing state parameter."
    return redirect(url_for("auth.logout_error", reason=reason))


@auth_bp.route("/logout/success")
def logout_success() -> str:
    """Display logout success page."""
    return render_template("auth/logout/success.html")


@auth_bp.route("/logout/error")
def logout_error() -> str:
    """Display logout error page."""
    reason = request.args.get("reason", "An unknown error occurred.")
    return render_template("auth/logout/error.html", reason=reason)


@auth_bp.route("/error")
def error_page() -> str:
    """Display authentication error page."""
    error_code = request.args.get("error")
    msg = get_message(error_code, "auth-error")
    return render_template("auth/error.html", **msg)


@auth_bp.route("/userinfo")
@require_auth
def userinfo() -> Any:
    """Fetch fresh user information from ZITADEL."""
    auth_session = session.get("auth_session", {})
    access_token = auth_session.get("access_token")

    if not access_token:
        logger.warning("Userinfo request without access token")
        return {"error": "No access token available"}, 401

    try:
        metadata = oauth.zitadel.load_server_metadata()
        userinfo_endpoint = metadata.get("userinfo_endpoint")

        headers = {"Authorization": f"Bearer {access_token}"}
        response = oauth.zitadel._client.get(userinfo_endpoint, headers=headers)
        response.raise_for_status()

        logger.info("Userinfo fetched successfully")
        result: dict[str, Any] = response.json()
        return result

    except Exception as e:
        logger.exception("Userinfo fetch failed: %s", str(e))
        return {"error": "Failed to fetch user info"}, 500


def register_auth_routes(app: Flask) -> None:
    """Register authentication blueprint with Flask application."""
    init_oauth(app)
    app.register_blueprint(auth_bp)
    logger.info("Authentication routes registered")
