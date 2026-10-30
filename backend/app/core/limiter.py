import hashlib

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

# Counters live in Redis so limits are shared across uvicorn workers and
# restarts; falls back to in-memory if Redis is briefly unavailable.
# The client address comes from nginx's X-Forwarded-For (uvicorn --proxy-headers).
# Tests use in-memory storage so no Redis is required.
_storage = "memory://" if settings.ENVIRONMENT == "test" else settings.REDIS_URL

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_storage,
    in_memory_fallback_enabled=True,
)


def agent_token_key(request) -> str:
    """Agents share NAT'd office IPs, so limit them per agent token instead of per IP."""
    token = request.headers.get("x-agent-token")
    if token:
        return "agent:" + hashlib.sha256(token.encode()).hexdigest()[:32]
    return get_remote_address(request)
