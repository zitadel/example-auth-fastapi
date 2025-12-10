"""Application entry point for the Flask ZITADEL authentication demo.

This module creates and runs the Flask application. It loads configuration
from environment variables and starts the development server.
"""

from __future__ import annotations

import os

import uvicorn
from lib.config import config

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.getenv("HOST", "localhost"),
        port=int(config.PORT or 3000),
        reload=config.PY_ENV != "production",
    )
