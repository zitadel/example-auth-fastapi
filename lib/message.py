"""Error message handling for authentication flows."""

from __future__ import annotations

from typing import Optional


def _signin_error_message(error_code: str) -> dict[str, str]:
    """Get error message for sign-in flow errors."""
    signin_errors = {
        "signin",
        "oauthsignin",
        "oauthcallback",
        "oauthcreateaccount",
        "emailcreateaccount",
        "callback",
    }

    if error_code in signin_errors:
        return {
            "heading": "Sign-in Failed",
            "message": "Try signing in with a different account.",
        }

    if error_code == "oauthaccountnotlinked":
        return {
            "heading": "Account Not Linked",
            "message": "To confirm your identity, sign in with the same account you used originally.",
        }

    if error_code == "emailsignin":
        return {
            "heading": "Email Not Sent",
            "message": "The email could not be sent.",
        }

    if error_code == "credentialssignin":
        return {
            "heading": "Sign-in Failed",
            "message": "Sign in failed. Check the details you provided are correct.",
        }

    if error_code == "sessionrequired":
        return {
            "heading": "Sign-in Required",
            "message": "Please sign in to access this page.",
        }

    return {
        "heading": "Unable to Sign in",
        "message": "An unexpected error occurred during sign-in. Please try again.",
    }


def _auth_error_message(error_code: str) -> dict[str, str]:
    """Get error message for general authentication errors."""
    if error_code == "configuration":
        return {
            "heading": "Server Error",
            "message": "There is a problem with the server configuration. Check the server logs for more information.",
        }

    if error_code == "accessdenied":
        return {
            "heading": "Access Denied",
            "message": "You do not have permission to sign in.",
        }

    if error_code == "verification":
        return {
            "heading": "Sign-in Link Invalid",
            "message": "The sign-in link is no longer valid. It may have been used already or it may have expired.",
        }

    return {
        "heading": "Authentication Error",
        "message": "An unexpected error occurred during authentication. Please try again.",
    }


def get_message(error_input: str | list[str] | None, category: str) -> dict[str, str]:
    """Retrieve a user-friendly error message based on error code and category."""
    raw: Optional[str]
    if isinstance(error_input, list) and error_input:
        raw = error_input[0]
    else:
        raw = error_input if isinstance(error_input, str) else None

    error_code = str(raw).lower() if raw is not None else "default"

    if category == "signin-error":
        return _signin_error_message(error_code)

    if category == "auth-error":
        return _auth_error_message(error_code)

    return {"heading": "Unknown Error", "message": "An unknown error occurred."}
