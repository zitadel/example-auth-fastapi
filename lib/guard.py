"""Authentication guard middleware with automatic token refresh.

This module provides middleware to protect routes requiring authentication,
automatically refreshing expired access tokens using refresh tokens when
necessary. Unauthenticated requests are redirected to the sign-in page.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import Request
from fastapi.responses import RedirectResponse, Response

logger = logging.getLogger(__name__)


class RedirectError(Exception):
    """Exception raised to trigger HTTP redirects for authentication flows.

    This exception is used internally to signal that a user needs to be
    redirected (e.g., to the sign-in page). It's caught by the global
    exception handler which converts it to a proper HTTP redirect response.

    Attributes:
        url: The URL to redirect to
    """

    def __init__(self, url: str) -> None:
        """Initialize the redirect exception.

        Args:
            url: The destination URL for the redirect
        """
        self.url = url
        super().__init__(f"Redirect to: {url}")


async def refresh_access_token(auth_session: dict[str, Any]) -> dict[str, Any] | None:
    """Automatically refresh an expired access token using the refresh token.

    When a user's access token expires (typically after 1 hour), this function
    seamlessly exchanges the refresh token for a new access token, allowing the
    user to continue using the application without having to log in again.

    This is essential for maintaining long-lived sessions and preventing users
    from being unexpectedly logged out during active use of the application.

    Args:
        auth_session: The current authentication session containing the refresh token

    Returns:
        Updated auth_session with new tokens on success, None on failure

    Example:
        >>> session = {"refresh_token": "...", "expires_at": 1234567890}
        >>> refreshed = await refresh_access_token(session)
        >>> if refreshed:
        ...     print("Token refreshed successfully")
    """
    refresh_token = auth_session.get("refresh_token")
    if not refresh_token:
        logger.error("No refresh token available for refresh")
        auth_session["error"] = "RefreshAccessTokenError"
        return None

    try:
        from lib.auth import oauth

        metadata = await oauth.zitadel.load_server_metadata()
        token_endpoint = metadata.get("token_endpoint")

        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        response = await oauth.zitadel.async_client.post(
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


async def require_auth(request: Request) -> dict[str, Any]:
    """Ensure the user is authenticated before accessing protected routes.

    This dependency retrieves the current authentication session and validates
    that a user is present. If authentication fails or the token has expired,
    it attempts to refresh the token or redirects to the sign-in page.

    The function is designed to be used as a FastAPI dependency via Depends(),
    providing a clean way to protect routes while automatically handling token
    refresh and authentication redirects.

    Args:
        request: The incoming HTTP request containing session data

    Returns:
        The authenticated session data including user info and tokens

    Raises:
        RedirectError: When authentication fails, redirecting to sign-in page

    Example:
        >>> @app.get("/profile")
        >>> async def profile(
        ...     request: Request,
        ...     auth_session: dict = Depends(require_auth)
        ... ):
        ...     return {"user": auth_session["user"]}
    """
    session = request.session
    auth_session: dict[str, Any] | None = session.get("auth_session")

    if not auth_session or not auth_session.get("user"):
        callback_url = str(request.url)
        logger.info("Unauthenticated access attempt, redirecting to signin")
        raise RedirectError(f"{request.url_for('signin')}?callbackUrl={callback_url}")

    if auth_session.get("error"):
        logger.warning("Session has error flag, redirecting to signin")
        session.clear()
        callback_url = str(request.url)
        raise RedirectError(f"{request.url_for('signin')}?callbackUrl={callback_url}")

    expires_at = auth_session.get("expires_at")
    if expires_at and int(time.time()) >= expires_at:
        logger.info("Access token expired, attempting refresh")
        refreshed_session = await refresh_access_token(auth_session)

        if refreshed_session:
            session["auth_session"] = refreshed_session
            return refreshed_session
        else:
            logger.error("Token refresh failed, clearing session")
            session.clear()
            callback_url = str(request.url)
            raise RedirectError(f"{request.url_for('signin')}?callbackUrl={callback_url}")

    return auth_session


def redirect_exception_handler(request: Request, exc: Exception) -> Response:
    """Convert RedirectError exceptions into HTTP redirect responses.

    This exception handler is registered globally with the FastAPI application
    to catch RedirectError exceptions and convert them into proper HTTP 307
    redirect responses. This allows the authentication guard to use exceptions
    for control flow while maintaining clean separation of concerns.

    Args:
        request: The incoming HTTP request (unused but required by FastAPI)
        exc: The exception to handle

    Returns:
        RedirectResponse with status 307 if exc is RedirectError

    Raises:
        Exception: Re-raises the exception if it's not a RedirectError
    """
    if not isinstance(exc, RedirectError):
        raise exc
    return RedirectResponse(url=exc.url, status_code=307)
