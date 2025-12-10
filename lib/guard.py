"""Authentication guard middleware with automatic token refresh."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict

from fastapi import Request
from fastapi.responses import RedirectResponse, Response

logger = logging.getLogger(__name__)


class RedirectError(Exception):
    """Internal exception used to trigger redirect logic."""

    def __init__(self, url: str) -> None:
        self.url = url


async def refresh_access_token(auth_session: Dict[str, Any]) -> Dict[str, Any] | None:
    """Automatically refresh an expired access token using the refresh token."""
    refresh_token = auth_session.get("refresh_token")
    if not refresh_token:
        auth_session["error"] = "RefreshAccessTokenError"
        return None

    try:
        from lib.auth import oauth

        metadata = await oauth.zitadel.load_server_metadata()
        endpoint = metadata.get("token_endpoint")

        response = await oauth.zitadel.async_client.post(
            endpoint,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            },
            auth=(oauth.zitadel.client_id, oauth.zitadel.client_secret),
        )
        response.raise_for_status()

        new_token = response.json()

        auth_session["access_token"] = new_token.get("access_token")
        auth_session["expires_at"] = new_token.get("expires_at", int(time.time()) + 3600)
        auth_session["refresh_token"] = new_token.get("refresh_token", refresh_token)
        auth_session["error"] = None

        return auth_session

    except Exception:
        auth_session["error"] = "RefreshAccessTokenError"
        return None


async def require_auth(request: Request) -> Dict[str, Any]:
    """Middleware that ensures the user is authenticated before accessing protected routes."""
    session = request.session
    auth_session: Dict[str, Any] | None = session.get("auth_session")

    if not auth_session or not auth_session.get("user"):
        cb = str(request.url)
        raise RedirectError(f"{request.url_for('signin')}?callbackUrl={cb}")

    if auth_session.get("error"):
        session.clear()
        cb = str(request.url)
        raise RedirectError(f"{request.url_for('signin')}?callbackUrl={cb}")

    expires_at = auth_session.get("expires_at")
    if expires_at and int(time.time()) >= expires_at:
        refreshed = await refresh_access_token(auth_session)
        if refreshed is None:
            session.clear()
            cb = str(request.url)
            raise RedirectError(f"{request.url_for('signin')}?callbackUrl={cb}")

        session["auth_session"] = refreshed
        assert refreshed is not None
        return refreshed

    return auth_session


def redirect_exception_handler(request: Request, exc: Exception) -> Response:
    """Translate internal redirect exceptions into RedirectResponse."""
    if not isinstance(exc, RedirectError):
        raise exc
    return RedirectResponse(url=exc.url, status_code=307)
