"""Authentication guard middleware with automatic token refresh."""

from __future__ import annotations

import logging
import time
from functools import wraps
from typing import Any, Callable, TypeVar, cast

from flask import Response, g, redirect, request, session, url_for

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def refresh_access_token(auth_session: dict[str, Any]) -> dict[str, Any] | None:
    """Automatically refresh an expired access token using the refresh token."""
    refresh_token = auth_session.get("refresh_token")
    if not refresh_token:
        logger.error("No refresh token available for refresh")
        auth_session["error"] = "RefreshAccessTokenError"
        return None

    try:
        from lib.auth import oauth

        metadata = oauth.zitadel.load_server_metadata()
        token_endpoint = metadata.get("token_endpoint")

        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        response = oauth.zitadel._client.post(
            token_endpoint,
            data=token_data,
            auth=(oauth.zitadel.client_id, oauth.zitadel.client_secret),
        )
        response.raise_for_status()
        new_token = response.json()

        auth_session["access_token"] = new_token.get("access_token")
        auth_session["expires_at"] = new_token.get("expires_at", int(time.time()) + 3600)
        auth_session["refresh_token"] = new_token.get("refresh_token", refresh_token)
        auth_session["error"] = None

        logger.info("Access token refreshed successfully")
        return auth_session

    except Exception as e:
        logger.exception("Token refresh failed: %s", str(e))
        auth_session["error"] = "RefreshAccessTokenError"
        return None


def require_auth(view: F) -> F:
    """Middleware that ensures the user is authenticated before accessing protected routes."""

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Response:
        auth_session = session.get("auth_session")

        if not auth_session or not auth_session.get("user"):
            callback_url = request.url
            logger.info("Unauthenticated access attempt, redirecting to signin")
            return cast(Response, redirect(url_for("auth.signin", callbackUrl=callback_url, _external=False)))

        if auth_session.get("error"):
            logger.warning("Session has error flag, redirecting to signin")
            session.clear()
            callback_url = request.url
            return cast(Response, redirect(url_for("auth.signin", callbackUrl=callback_url, _external=False)))

        expires_at = auth_session.get("expires_at")
        if expires_at and int(time.time()) >= expires_at:
            logger.info("Access token expired, attempting refresh")
            refreshed_session = refresh_access_token(auth_session)

            if refreshed_session:
                session["auth_session"] = refreshed_session
                g.auth_session = refreshed_session
            else:
                logger.error("Token refresh failed, clearing session")
                session.clear()
                callback_url = request.url
                return cast(Response, redirect(url_for("auth.signin", callbackUrl=callback_url, _external=False)))
        else:
            g.auth_session = auth_session

        return cast(Response, view(*args, **kwargs))

    return cast(F, wrapped)
