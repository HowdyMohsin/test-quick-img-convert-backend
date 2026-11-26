"""Test captcha verification (v5 register hardening).

POST /v1/captcha/verify {token} -> {ok: bool}. The token is verified
against Google's reCAPTCHA siteverify endpoint with the secret from the
RECAPTCHA_SECRET_KEY env var. When the env var is unset, Google's
official TEST secret is used, so test mode always passes (Google's test
keys accept any non-empty token and always return success).

Fail closed: a missing/empty token returns ok:false immediately, and an
unreachable Google returns ok:false with an error. The secret is never
logged.
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/v1/captcha", tags=["captcha"])

SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"
# Google's official test secret (public, documented): with the test site
# key it always verifies. Used only when RECAPTCHA_SECRET_KEY is unset.
TEST_SECRET_KEY = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"


class CaptchaVerifyBody(BaseModel):
    token: str = ""


def _verify_with_google(secret: str, token: str) -> bool | None:
    """POST the token to siteverify. Returns True/False on a Google
    answer, None when Google cannot be reached."""
    data = urllib.parse.urlencode(
        {"secret": secret, "response": token}).encode("utf-8")
    request = urllib.request.Request(
        SITEVERIFY_URL, data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return None
    return bool(payload.get("success"))


@router.post("/verify")
async def verify_captcha(body: CaptchaVerifyBody):
    token = (body.token or "").strip()
    if not token:
        return {"ok": False, "error": "missing_token",
                "message": "No captcha token was provided."}
    secret = os.environ.get("RECAPTCHA_SECRET_KEY", "") or TEST_SECRET_KEY
    result = await asyncio.to_thread(_verify_with_google, secret, token)
    if result is None:
        return {"ok": False, "error": "verification_unavailable",
                "message": "The captcha service could not be reached. Try again."}
    if not result:
        return {"ok": False, "error": "captcha_failed",
                "message": "Captcha verification failed. Try again."}
    return {"ok": True}
