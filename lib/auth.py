"""ZITADEL authentication routes using Authlib Flask integration."""

from __future__ import annotations

import logging
import secrets
from typing import Any, Dict, Optional, cast
from urllib.parse import urlencode

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, FastAPI, Form, Request
from fastapi.responses import RedirectResponse

from lib.config import config
from lib.guard import require_auth
from lib.message import get_message
from lib.scopes import ZITADEL_SCOPES

logger = logging.getLogger(__name__)

auth_bp = APIRouter(prefix="/auth")
oauth = OAuth()


def get_well_known_url(domain: str) -> str:
    return f"{domain}/.well-known/openid-configuration"


def init_oauth(app: FastAPI) -> None:
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


@auth_bp.get("/csrf")
async def csrf(request: Request) -> Dict[str, str]:
    """Generate CSRF token for form submissions."""
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrfToken": request.session["csrf_token"]}


@auth_bp.get("/signin")
async def signin(request: Request) -> Any:
    """Render the sign-in page."""
    templates = request.app.state.templates
    error = request.query_params.get("error")

    providers = [
        {
            "id": "zitadel",
            "name": "ZITADEL",
            "signinUrl": request.url_for("auth_signin_zitadel"),
        }
    ]

    return templates.TemplateResponse(
        request=request,
        name="auth/signin.html",
        context={
            "url_for": request.url_for,
            "providers": providers,
            "callbackUrl": request.query_params.get("callbackUrl") or config.ZITADEL_POST_LOGIN_URL,
            "message": get_message(error, "signin-error") if error else None,
        },
    )


@auth_bp.post("/signin/zitadel", name="auth_signin_zitadel")
async def signin_zitadel(
    request: Request,
    csrf_token: str = Form(..., alias="csrfToken"),
    callback_url: Optional[str] = Form(None, alias="callbackUrl"),
) -> RedirectResponse:
    """Initiate OAuth 2.0 authorization flow with PKCE."""
    stored_token = request.session.get("csrf_token")

    if not csrf_token or not stored_token or not secrets.compare_digest(csrf_token, stored_token):
        return RedirectResponse(f"{request.url_for('signin')}?error=verification", status_code=302)

    request.session.pop("csrf_token", None)
    request.session["post_login_url"] = callback_url or config.ZITADEL_POST_LOGIN_URL

    redirect_uri = config.ZITADEL_CALLBACK_URL
    resp = await oauth.zitadel.authorize_redirect(request, redirect_uri)
    return cast(RedirectResponse, resp)


@auth_bp.get("/callback")
async def callback(request: Request) -> RedirectResponse:
    """Handle OAuth 2.0 callback from ZITADEL."""
    try:
        token = await oauth.zitadel.authorize_access_token(request)
        userinfo = await oauth.zitadel.userinfo(token=token)

        previous = dict(request.session)
        request.session.clear()

        if "post_login_url" in previous:
            request.session["post_login_url"] = previous["post_login_url"]

        request.session["auth_session"] = {
            "user": userinfo,
            "access_token": token.get("access_token"),
            "id_token": token.get("id_token"),
            "refresh_token": token.get("refresh_token"),
            "expires_at": token.get("expires_at"),
        }

        url = request.session.pop("post_login_url", config.ZITADEL_POST_LOGIN_URL)
        return RedirectResponse(url, status_code=302)

    except Exception as e:
        logger.exception("Callback error: %s", e)
        return RedirectResponse(f"{request.url_for('error_page')}?error=callback", status_code=302)


@auth_bp.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    """Initiate logout flow with ZITADEL."""
    try:
        logout_state = secrets.token_urlsafe(32)
        request.session["logout_state"] = logout_state

        metadata = await oauth.zitadel.load_server_metadata()
        endpoint = metadata.get("end_session_endpoint")

        if endpoint:
            params = {
                "post_logout_redirect_uri": config.ZITADEL_POST_LOGOUT_URL,
                "client_id": config.ZITADEL_CLIENT_ID,
                "state": logout_state,
            }
            return RedirectResponse(f"{endpoint}?{urlencode(params)}", status_code=302)

        request.session.clear()
        return RedirectResponse(config.ZITADEL_POST_LOGOUT_URL, status_code=302)

    except Exception:
        request.session.clear()
        return RedirectResponse(config.ZITADEL_POST_LOGOUT_URL, status_code=302)


@auth_bp.get("/logout/callback")
async def logout_callback(request: Request) -> RedirectResponse:
    """Handle logout callback from ZITADEL with state validation."""
    received = request.query_params.get("state")
    stored = request.session.get("logout_state")

    if received and stored and secrets.compare_digest(received, stored):
        request.session.clear()
        return RedirectResponse(request.url_for("logout_success"), status_code=302)

    reason = "Invalid or missing state parameter."
    return RedirectResponse(f"{request.url_for('logout_error')}?reason={reason}", status_code=302)


@auth_bp.get("/logout/success")
async def logout_success(request: Request) -> Any:
    templates = request.app.state.templates
    return templates.TemplateResponse(request=request, name="auth/logout/success.html")


@auth_bp.get("/logout/error")
async def logout_error(request: Request) -> Any:
    templates = request.app.state.templates
    reason = request.query_params.get("reason", "Unknown error")
    return templates.TemplateResponse(request=request, name="auth/logout/error.html", context={"reason": reason})


@auth_bp.get("/error")
async def error_page(request: Request) -> Any:
    templates = request.app.state.templates
    error_code = request.query_params.get("error")
    msg = get_message(error_code, "auth-error")
    return templates.TemplateResponse(request=request, name="auth/error.html", context=msg)


@auth_bp.get("/userinfo")
async def userinfo(request: Request) -> Dict[str, Any]:
    """Fetch fresh user information from ZITADEL."""
    auth_session = await require_auth(request)
    access_token = auth_session.get("access_token")
    if not access_token:
        return {"error": "No access token available"}

    try:
        metadata = await oauth.zitadel.load_server_metadata()
        endpoint = metadata.get("userinfo_endpoint")

        response = await oauth.zitadel.async_client.get(
            endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        response.raise_for_status()

        return cast(Dict[str, Any], response.json())

    except Exception:
        return {"error": "Failed to fetch user info"}


def register_auth_routes(app: FastAPI, templates: Any) -> None:
    """Register authentication blueprint with Flask application."""
    app.state.templates = templates
    init_oauth(app)
    app.include_router(auth_bp)
