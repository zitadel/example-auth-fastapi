from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from lib.guard import require_auth

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def home(request: Request) -> Any:
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
    user_json = json.dumps(auth_session.get("user", {}), indent=2)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={
            "url_for": request.url_for,
            "userJson": user_json,
        },
    )
