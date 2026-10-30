"""
Structured-log configuration with secret redaction.

Any log field whose name looks sensitive is replaced with "[REDACTED]" before it is
rendered, so a stray `log.info(..., password=pw)` or `token=...` cannot leak secrets.
Do not log raw request bodies, Authorization headers or full exception text from
HTTP clients (their messages can embed URLs/keys); log the exception type instead.
"""
import re

import structlog

_SENSITIVE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|authorization|cookie|bind_password|credential)", re.I
)


def redact_sensitive(_logger, _method, event_dict: dict) -> dict:
    for key in list(event_dict):
        if key != "event" and _SENSITIVE.search(key):
            event_dict[key] = "[REDACTED]"
    return event_dict


def configure_logging() -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            redact_sensitive,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
    )
