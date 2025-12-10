"""Basic smoke tests for application."""

from __future__ import annotations

from app import create_app


def test_app_starts() -> None:
    """Test that application starts successfully."""
    app = create_app()
    assert app is not None


def test_home_page_loads() -> None:
    """Test that home page loads and returns 200."""
    app = create_app()
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200


def test_signin_page_loads() -> None:
    """Test that sign-in page loads."""
    app = create_app()
    client = app.test_client()
    response = client.get("/auth/signin")
    assert response.status_code == 200


def test_profile_redirects_when_unauthenticated() -> None:
    """Test that profile page redirects to sign-in when not authenticated."""
    app = create_app()
    client = app.test_client()
    response = client.get("/profile", follow_redirects=False)
    assert response.status_code == 302


def test_csrf_endpoint_works() -> None:
    """Test that CSRF endpoint returns a token."""
    app = create_app()
    client = app.test_client()
    response = client.get("/auth/csrf")
    assert response.status_code == 200
