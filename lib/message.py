"""Error message handling for authentication flows.

Provides user-friendly error messages for various authentication failure
scenarios, translating technical error codes into helpful guidance.
"""

from __future__ import annotations

from typing import Optional


def _signin_error_message(error_code: str) -> dict[str, str]:
    """Get error message for sign-in flow errors.

    Args:
        error_code: The error code from the authentication flow

    Returns:
        dict: Contains 'heading' and 'message' for display
    """
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
    """Get error message for general authentication errors.

    Args:
        error_code: The error code from the authentication system

    Returns:
        dict: Contains 'heading' and 'message' for display
    """
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
    """Retrieve a user-friendly error message based on error code and category.

    Args:
        error_input: Error code string, list of strings, or None
        category: Either 'signin-error' or 'auth-error'

    Returns:
        dict: Contains 'heading' and 'message' keys with error text
    """
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
