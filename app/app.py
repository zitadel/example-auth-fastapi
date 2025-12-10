from app import create_app

# This file exists only so that external runners (like poetry, flask, etc.)
# can import the Flask app cleanly without touching run.py.

app = create_app()
