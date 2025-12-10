import os

os.environ.setdefault("PORT", "3000")
os.environ.setdefault("SESSION_DURATION", "3600")
os.environ.setdefault("SESSION_SECRET", "test-secret-key-for-pytest")
os.environ.setdefault("ZITADEL_DOMAIN", "https://test.us1.zitadel.cloud")
os.environ.setdefault("ZITADEL_CLIENT_ID", "mock-client-id")
os.environ.setdefault("ZITADEL_CLIENT_SECRET", "mock-client-secret")
os.environ.setdefault("ZITADEL_CALLBACK_URL", "http://localhost:3000/auth/callback")
os.environ.setdefault("ZITADEL_POST_LOGOUT_URL", "http://localhost:3000/auth/logout/callback")
