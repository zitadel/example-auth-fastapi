# FastAPI with ZITADEL

[FastAPI](https://fastapi.tiangolo.com/) is a modern ASGI web application framework for Python. It's designed to make getting started quick and easy, with the ability to scale up to complex applications. FastAPI provides the tools, libraries, and patterns to build secure web applications efficiently.

To secure such an application, you need a reliable way to handle user logins. For FastAPI applications, [Authlib](https://authlib.org/) is the standard and recommended library for authentication. Think of it as a flexible security guard for your app. This guide demonstrates how to use Authlib with a FastAPI application to implement a secure login with ZITADEL.

We'll be using the **OpenID Connect (OIDC)** protocol with the **Authorization Code Flow + PKCE**. This is the industry-best practice for security, ensuring that the login process is safe from start to finish. You can learn more in our [guide to OAuth 2.0 recommended flows](https://zitadel.com/docs/guides/integrate/login/oidc/oauth-recommended-flows).

This example uses **Authlib**, the standard for FastAPI authentication. While ZITADEL doesn't offer a specific SDK, Authlib is highly modular. It works with FastAPI through Starlette's integration layer that handles communication with ZITADEL. Under the hood, this example uses the powerful OIDC standard to manage the secure PKCE flow.

Check out our Example Application to see it in action.

## Example Application

The example repository includes a complete FastAPI application, ready to run, that demonstrates how to integrate ZITADEL for user authentication.

This example application showcases a typical web app authentication pattern: users start on a public landing page, click a login button to authenticate with ZITADEL, and are then redirected to a protected profile page displaying their user information. The app also includes secure logout functionality that clears the session and redirects users back to ZITADEL's logout endpoint. All protected routes are automatically secured using Authlib middleware and session management, ensuring only authenticated users can access sensitive areas of your application.

### Prerequisites

Before you begin, ensure you have the following:

#### System Requirements

- Python (v3.10 or later)
- Poetry package manager

#### Account Setup

You'll need a ZITADEL account and application configured. Follow the [ZITADEL documentation on creating applications](https://zitadel.com/docs/guides/integrate/login/oidc/web-app) to set up your account and create a Web application with Authorization Code + PKCE flow.

> **Important:** Configure the following URLs in your ZITADEL application settings:
>
> - **Redirect URIs:** Add `http://localhost:3000/auth/callback` (for development)
> - **Post Logout Redirect URIs:** Add `http://localhost:3000/auth/logout/callback` (for development)
>
> These URLs must exactly match what your FastAPI application uses. For production, add your production URLs.

### Configuration

To run the application, you first need to copy the `.env.example` file to a new file named `.env` and fill in your ZITADEL application credentials.

```dotenv
# Port number where your FastAPI server will listen for incoming HTTP requests.
PORT=3000

# Session timeout in seconds. Users will be automatically logged out after this
# duration of inactivity. 3600 seconds = 1 hour.
SESSION_DURATION=3600

# Secret key used to cryptographically sign session cookies to prevent
# tampering. MUST be a long, random string. Generate a secure key using:
# python -c "import secrets; print(secrets.token_hex(32))"
SESSION_SECRET="your-very-secret-and-strong-session-key"

# Your ZITADEL instance domain URL. Found in your ZITADEL console under
# instance settings. Include the full https:// URL.
ZITADEL_DOMAIN="https://your-zitadel-domain"

# Application Client ID from your ZITADEL application settings.
ZITADEL_CLIENT_ID="your-client-id"

# While the Authorization Code Flow with PKCE for public clients
# does not strictly require a client secret for OIDC specification compliance,
# Authlib will still require a value for its internal configuration.
# Therefore, please provide a randomly generated string here.
ZITADEL_CLIENT_SECRET="your-randomly-generated-client-secret"

# OAuth callback URL where ZITADEL redirects after user authentication.
# MUST exactly match a Redirect URI configured in your ZITADEL application.
ZITADEL_CALLBACK_URL="http://localhost:3000/auth/callback"

# URL where users are redirected after successful login.
ZITADEL_POST_LOGIN_URL="/profile"

# URL where users are redirected after logout.
ZITADEL_POST_LOGOUT_URL="http://localhost:3000/auth/logout/callback"
```

### Installation and Running

Follow these steps to get the application running:

```bash
# 1. Clone the repository
git clone git@github.com:zitadel/example-fastapi-auth.git
cd example-fastapi-auth

# 2. Install the project dependencies
poetry install

# 3. Start the development server
poetry run python run.py
```

The application will now be running at `http://localhost:3000`.

## Key Features

### PKCE Authentication Flow

The application implements the secure Authorization Code Flow with PKCE (Proof Key for Code Exchange), which is the recommended approach for modern web applications.

### Session Management

Built-in session management with FastAPI and Starlette handles user authentication state across your application, with secure cookie storage.

### Route Protection

Protected routes automatically redirect unauthenticated users to the login flow, ensuring sensitive areas of your application remain secure.

### Logout Flow

Complete logout implementation that properly terminates both the local session and the ZITADEL session, with proper redirect handling.

## TODOs

### 1. Security headers (FastAPI middleware)

**Not enabled.** Consider adding security headers middleware in your FastAPI application:

```python
from secure import Secure
from fastapi import FastAPI
from fastapi.responses import Response

secure_headers = Secure()
app = FastAPI()

@app.middleware("http")
async def set_secure_headers(request, call_next):
    response: Response = await call_next(request)
    secure_headers.framework.fastapi(response)
    return response
```

At minimum, configure:

- `Content-Security-Policy` (CSP)
- `X-Frame-Options` / `frame-ancestors`
- `Referrer-Policy`
- `Permissions-Policy`

## Resources

- **FastAPI Documentation:** <https://fastapi.tiangolo.com/>
- **Authlib Documentation:** <https://authlib.org/>
- **ZITADEL Documentation:** <https://zitadel.com/docs>
