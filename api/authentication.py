"""
api/authentication.py
=====================
Two simple protections for the Guardian web server:

1. TOKEN CHECK  - Nemesis must send  "Authorization: Bearer <SHIRO_API_TOKEN>".
                  Without the right token the server answers 401.
2. LOCAL-ONLY   - The dashboard pages/data can only be opened from the ASUS
                  laptop itself (127.0.0.1), not from other devices on Wi-Fi.
"""
from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def make_token_checker(expected_token: str):
    """Return a FastAPI dependency that checks the Bearer token."""

    def check_token(request: Request) -> None:
        header = request.headers.get("authorization", "")
        scheme, _, supplied = header.partition(" ")
        if scheme.lower() != "bearer" or not supplied:
            raise HTTPException(status_code=401, detail="Missing bearer token")
        # compare_digest avoids timing attacks
        if not hmac.compare_digest(supplied.strip().encode(), expected_token.encode()):
            raise HTTPException(status_code=401, detail="Invalid token")

    return check_token


def make_local_only_checker(allow_remote: bool):
    """Return a dependency that only lets the local machine through."""

    def check_local(request: Request) -> None:
        if allow_remote:
            return
        host = request.client.host if request.client else ""
        if host not in LOCAL_HOSTS:
            raise HTTPException(
                status_code=403,
                detail="Dashboard is local-only. Open it on the ASUS laptop at http://127.0.0.1:8000",
            )

    return check_local
