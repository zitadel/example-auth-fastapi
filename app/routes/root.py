"""Application root routes for public and protected pages.

This module defines the main application routes including the home page
and user profile page. Protected routes require authentication via the
require_auth dependency.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from lib.guard import require_auth

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def home(request: Request) -> Any:
    """Render the home page with authentication status.

    Displays the landing page showing whether the user is authenticated
    and providing a login button if they are not.

    Args:
        request: The incoming HTTP request

    Returns:
        TemplateResponse: Rendered home page
    """
    session_data = request.session.get("auth_session")
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "url_for": request.url_for,
            "isAuthenticated": bool(session_data),
            "loginUrl": request.url_for("auth_signin_zitadel"),
        },
    )


@router.get("/profile", response_class=HTMLResponse)
async def profile(
    request: Request,
    auth_session: dict[str, Any] = Depends(require_auth),  # noqa: B008
) -> Any:
    """Display authenticated user's profile information.

    Shows comprehensive user profile data including identity claims,
    roles, and session metadata. This route is protected and requires
    authentication via the require_auth dependency.

    Args:
        request: The incoming HTTP request
        auth_session: The authenticated session data from require_auth dependency

    Returns:
        TemplateResponse: Rendered profile page with user data
    """
    user_json = json.dumps(auth_session.get("user", {}), indent=2)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={
            "url_for": request.url_for,
            "userJson": user_json,
        },
    )
