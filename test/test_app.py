"""Basic smoke tests for application."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app import create_app


def test_app_starts() -> None:
    app = create_app()
    assert app is not None


def test_home_page_loads() -> None:
    app = create_app()
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200


def test_signin_page_loads() -> None:
    """Matches Flask test exactly: GET /auth/signin"""
    app = create_app()
    client = TestClient(app)
    response = client.get("/auth/signin")
    assert response.status_code == 200


def test_profile_redirects_when_unauthenticated() -> None:
    """Same behavior as Flask—redirect if not logged in."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code in (302, 307)


def test_csrf_endpoint_works() -> None:
    """Same test as Flask—just checks 200."""
    app = create_app()
    client = TestClient(app)
    response = client.get("/auth/csrf")
    assert response.status_code == 200
