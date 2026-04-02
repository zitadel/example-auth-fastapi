.PHONY: help check start

help:
	@echo "Usage:"
	@echo "  make start   Start the development server"
	@echo "  make check   Verify required dependencies are installed"

check:
	@command -v python3 >/dev/null 2>&1 || { \
		echo "Error: Python 3 is not installed." >&2; \
		echo "" >&2; \
		echo "  Install it from https://www.python.org/downloads/ or use your package manager:" >&2; \
		echo "    brew install python         # macOS" >&2; \
		echo "    sudo apt install python3    # Ubuntu/Debian" >&2; \
		exit 1; \
	}
	@command -v uv >/dev/null 2>&1 || { \
		echo "Error: uv is not installed." >&2; \
		echo "" >&2; \
		echo "  Install it with:" >&2; \
		echo "    curl -LsSf https://astral.sh/uv/install.sh | sh" >&2; \
		echo "" >&2; \
		echo "  Or see https://docs.astral.sh/uv/getting-started/installation/" >&2; \
		exit 1; \
	}
	@test -f .env || { \
		echo "Error: Missing .env file." >&2; \
		echo "" >&2; \
		echo "  Copy the example file and fill in your Zitadel credentials:" >&2; \
		echo "    cp .env.example .env" >&2; \
		exit 1; \
	}

start: check
	uv sync --group dev
	uv run python run.py
