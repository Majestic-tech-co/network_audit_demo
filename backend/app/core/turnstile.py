"""
Cloudflare Turnstile verification for public (unauthenticated) forms.

Enabled when TURNSTILE_SECRET_KEY is set; otherwise the check is skipped so local/dev
setups work without a Cloudflare account. The browser sends the widget token in the
`X-Turnstile-Token` header.
"""
import httpx
import structlog
from fastapi import HTTPException, Request

from app.core.config import settings

log = structlog.get_logger()

SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


async def verify_turnstile(request: Request) -> None:
    secret = settings.TURNSTILE_SECRET_KEY
    if not secret:
        return

    token = request.headers.get("x-turnstile-token", "")
    if not token or len(token) > 2048:
        raise HTTPException(status_code=400, detail="CAPTCHA verification failed")

    data = {"secret": secret, "response": token}
    if request.client:
        data["remoteip"] = request.client.host
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(SITEVERIFY_URL, data=data)
        ok = resp.status_code == 200 and resp.json().get("success") is True
    except Exception as e:
        # Fail closed: if the check cannot be done, do not let the request through.
        log.error("turnstile_unreachable", error=type(e).__name__)
        raise HTTPException(status_code=503, detail="CAPTCHA verification unavailable. Try again.")
    if not ok:
        raise HTTPException(status_code=400, detail="CAPTCHA verification failed")
