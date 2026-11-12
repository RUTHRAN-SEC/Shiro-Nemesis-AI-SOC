"""
Makes a long random secret token. Run it ONCE, then paste the result into
SN_TOKEN=... in the .env file on BOTH laptops.

    python scripts/generate_token.py
"""
import secrets

print(secrets.token_urlsafe(32))
