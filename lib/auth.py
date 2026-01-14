"""ZITADEL authentication routes using Authlib Starlette integration.

This module implements OAuth 2.0 / OIDC authentication flows with ZITADEL,
including login, logout, callback handling, and user information retrieval.
All routes follow the Authorization Code Flow with PKCE for maximum security.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any, Optional, cast
from urllib.parse import urlencode

# noinspection PyUnresolvedReferences
from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, FastAPI, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse

from lib.config import config
from lib.guard import require_auth
from lib.message import get_message
from lib.scopes import ZITADEL_SCOPES

logger = logging.getLogger(__name__)

auth_bp = APIRouter(prefix="/auth")
oauth = OAuth()


def get_well_known_url(domain: str) -> str:
    """Construct the OpenID Connect discovery URL for a given domain.

    Args:
        domain: The base domain of the ZITADEL instance

    Returns:
        str: The full URL to the .well-known/openid-configuration endpoint
    """
    return f"{domain}/.well-known/openid-configuration"


def init_oauth(app: FastAPI) -> None:
    """Initialize OAuth client with ZITADEL configuration.

    Registers the ZITADEL OAuth provider with Authlib, configuring it for
    PKCE authentication flow with the appropriate scopes.

    Args:
        app: The FastAPI application instance
    """
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
async def csrf(request: Request) -> dict[str, str]:
    """Generate CSRF token for form submissions.

    Creates a cryptographically secure token and stores it in the session
    for validation on form submission. This prevents Cross-Site Request
    Forgery attacks.

    Args:
        request: The incoming HTTP request

    Returns:
        dict: JSON response containing the CSRF token
    """
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrfToken": request.session["csrf_token"]}


@auth_bp.get("/signin")
async def signin(request: Request) -> Any:
    """Render the sign-in page with available authentication providers.

    Displays a custom sign-in page that shows available OAuth providers
    and handles authentication errors with user-friendly messaging.

    Args:
        request: The incoming HTTP request

    Returns:
        TemplateResponse: Rendered sign-in page
    """
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
    """Initiate OAuth 2.0 authorization flow with PKCE.

    Validates the CSRF token, stores the post-login redirect URL, and
    redirects the user to ZITADEL's authorization endpoint to begin
    the authentication flow.

    Args:
        request: The incoming HTTP request
        csrf_token: CSRF token from the form submission
        callback_url: Optional URL to redirect after successful authentication

    Returns:
        RedirectResponse: Redirect to ZITADEL authorization endpoint or error page
    """
    stored_token = request.session.get("csrf_token")

    if not csrf_token or not stored_token or not secrets.compare_digest(csrf_token, stored_token):
        logger.warning("CSRF token validation failed")
        return RedirectResponse(f"{request.url_for('signin')}?error=verification", status_code=302)

    request.session.pop("csrf_token", None)
    request.session["post_login_url"] = callback_url or config.ZITADEL_POST_LOGIN_URL

    redirect_uri = config.ZITADEL_CALLBACK_URL
    logger.info("Initiating OAuth authorization flow")
    resp = await oauth.zitadel.authorize_redirect(request, redirect_uri)
    return cast(RedirectResponse, resp)


@auth_bp.get("/callback")
async def callback(request: Request) -> RedirectResponse:
    """Handle OAuth 2.0 callback from ZITADEL.

    Exchanges the authorization code for access tokens, retrieves user
    information, and establishes an authenticated session. Preserves the
    post-login redirect URL through the authentication flow.

    Args:
        request: The incoming HTTP request containing authorization code

    Returns:
        RedirectResponse: Redirect to post-login URL or error page
    """
    try:
        token = await oauth.zitadel.authorize_access_token(request)
        userinfo = await oauth.zitadel.userinfo(token=token)

        old_session_data = dict(request.session)
        request.session.clear()
        for key, value in old_session_data.items():
            if key in ("post_login_url",):
                request.session[key] = value

        request.session["auth_session"] = {
            "user": userinfo,
            "access_token": token.get("access_token"),
            "id_token": token.get("id_token"),
            "refresh_token": token.get("refresh_token"),
            "expires_at": token.get("expires_at"),
        }

        post_login_url = request.session.pop("post_login_url", config.ZITADEL_POST_LOGIN_URL)
        logger.info(f"Authentication successful for user: {userinfo.get('sub')}")
        return RedirectResponse(post_login_url, status_code=302)

    except Exception as e:
        logger.exception("Token exchange failed: %s", str(e))
        return RedirectResponse(f"{request.url_for('error_page')}?error=callback", status_code=302)


@auth_bp.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    """Initiate logout flow with ZITADEL.

    Creates a logout state token for CSRF protection and redirects to
    ZITADEL's end session endpoint to terminate the SSO session.

    Args:
        request: The incoming HTTP request

    Returns:
        RedirectResponse: Redirect to ZITADEL logout endpoint or fallback URL
    """
    try:
        logout_state = secrets.token_urlsafe(32)
        request.session["logout_state"] = logout_state

        metadata = await oauth.zitadel.load_server_metadata()
        end_session_endpoint = metadata.get("end_session_endpoint")

        if end_session_endpoint:
            params = {
                "post_logout_redirect_uri": config.ZITADEL_POST_LOGOUT_URL,
                "client_id": config.ZITADEL_CLIENT_ID,
                "state": logout_state,
            }
            logout_url = f"{end_session_endpoint}?{urlencode(params)}"
            logger.info("Initiating logout flow")
            return RedirectResponse(logout_url, status_code=302)

        request.session.clear()
        return RedirectResponse(config.ZITADEL_POST_LOGOUT_URL, status_code=302)

    except Exception as e:
        logger.exception("Logout initiation failed: %s", str(e))
        request.session.clear()
        return RedirectResponse(config.ZITADEL_POST_LOGOUT_URL, status_code=302)


@auth_bp.get("/logout/callback")
async def logout_callback(request: Request) -> RedirectResponse:
    """Handle logout callback from ZITADEL with state validation.

    Validates the logout state parameter to prevent CSRF attacks, clears
    the local session, and redirects to the success or error page.

    Args:
        request: The incoming HTTP request with state parameter

    Returns:
        RedirectResponse: Redirect to logout success or error page
    """
    received_state = request.query_params.get("state")
    stored_state = request.session.get("logout_state")

    if received_state and stored_state and secrets.compare_digest(received_state, stored_state):
        request.session.clear()
        logger.info("Logout successful")
        return RedirectResponse(request.url_for("logout_success"), status_code=302)

    logger.warning("Logout state validation failed")
    reason = "Invalid or missing state parameter."
    return RedirectResponse(f"{request.url_for('logout_error')}?reason={reason}", status_code=302)


@auth_bp.get("/logout/success")
async def logout_success(request: Request) -> Any:
    """Display logout success page.

    Args:
        request: The incoming HTTP request

    Returns:
        TemplateResponse: Rendered logout success page
    """
    templates = request.app.state.templates
    return templates.TemplateResponse(request=request, name="auth/logout/success.html")


@auth_bp.get("/logout/error")
async def logout_error(request: Request) -> Any:
    """Display logout error page.

    Args:
        request: The incoming HTTP request

    Returns:
        TemplateResponse: Rendered logout error page with error reason
    """
    templates = request.app.state.templates
    reason = request.query_params.get("reason", "An unknown error occurred.")
    return templates.TemplateResponse(request=request, name="auth/logout/error.html", context={"reason": reason})


@auth_bp.get("/error")
async def error_page(request: Request) -> Any:
    """Display authentication error page.

    Shows user-friendly error messages for various authentication failures
    including configuration errors, access denied, and verification failures.

    Args:
        request: The incoming HTTP request with error code parameter

    Returns:
        TemplateResponse: Rendered error page with contextual message
    """
    templates = request.app.state.templates
    error_code = request.query_params.get("error")
    msg = get_message(error_code, "auth-error")
    return templates.TemplateResponse(request=request, name="auth/error.html", context=msg)


@auth_bp.get("/userinfo")
async def userinfo(
    request: Request,
    auth_session: dict[str, Any] = Depends(require_auth),  # noqa: B008
) -> JSONResponse:
    """Fetch fresh user information from ZITADEL's UserInfo endpoint.

    Retrieves the latest user information using the current access token.
    This provides real-time user data including roles, custom attributes,
    and organization membership.

    Args:
        request: The incoming HTTP request
        auth_session: The authenticated session data from require_auth dependency

    Returns:
        JSONResponse: User information from ZITADEL or error message with status code
    """
    access_token = auth_session.get("access_token")

    if not access_token:
        logger.warning("Userinfo request without access token")
        return JSONResponse({"error": "No access token available"}, status_code=401)

    try:
        metadata = await oauth.zitadel.load_server_metadata()
        userinfo_endpoint = metadata.get("userinfo_endpoint")

        headers = {"Authorization": f"Bearer {access_token}"}
        response = await oauth.zitadel.async_client.get(userinfo_endpoint, headers=headers)
        response.raise_for_status()

        logger.info("Userinfo fetched successfully")
        result: dict[str, Any] = response.json()
        return JSONResponse(result)

    except Exception as e:
        logger.exception("Userinfo fetch failed: %s", str(e))
        return JSONResponse({"error": "Failed to fetch user info"}, status_code=500)


def register_auth_routes(app: FastAPI, templates: Any) -> None:
    """Register authentication routes with the FastAPI application.

    Initializes OAuth client and includes all authentication-related routes
    under the /auth prefix.

    Args:
        app: The FastAPI application instance
        templates: Jinja2Templates instance for rendering
    """
    app.state.templates = templates
    init_oauth(app)
    app.include_router(auth_bp)
    logger.info("Authentication routes registered")
