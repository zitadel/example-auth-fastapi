"""Application entry point for the Flask ZITADEL authentication demo.

This module creates and runs the Flask application. It loads configuration
from environment variables and starts the development server.
"""

from __future__ import annotations

import os

from app import create_app
from lib.config import config

app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "localhost"),
        port=int(config.PORT or 3000),
        debug=config.PY_ENV != "production",
    )
