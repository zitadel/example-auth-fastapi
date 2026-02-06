.PHONY: start

start:
	poetry install
	poetry run python run.py
