.PHONY: start

start:
	uv sync --group dev
	uv run python run.py
