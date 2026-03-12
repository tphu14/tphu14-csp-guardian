# CSP Guardian v3 – services/sentry_service.py
# Sentry error tracking + performance profiling

import os
import logging
import functools
from typing import Callable, Any

logger = logging.getLogger("csp-guardian.sentry")

_sentry_enabled = False


def init_sentry():
    """Initialize Sentry SDK if DSN is configured."""
    global _sentry_enabled
    dsn = os.environ.get("SENTRY_DSN", "")
    if not dsn:
        logger.info("Sentry DSN not set – error tracking disabled")
        return

    try:
        import sentry_sdk
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
        from sentry_sdk.integrations.logging import LoggingIntegration

        sentry_sdk.init(
            dsn=dsn,
            environment=os.environ.get("ENV", "development"),
            release=f"csp-guardian@3.0.0",

            # Performance tracing
            traces_sample_rate=float(os.environ.get("SENTRY_TRACES_RATE", "0.2")),
            profiles_sample_rate=float(os.environ.get("SENTRY_PROFILES_RATE", "0.1")),

            integrations=[
                FastApiIntegration(transaction_style="endpoint"),
                SqlalchemyIntegration(),
                LoggingIntegration(
                    level=logging.WARNING,
                    event_level=logging.ERROR,
                ),
            ],

            # Strip PII
            send_default_pii=False,

            # Before send hook – scrub sensitive data
            before_send=_before_send,
        )
        _sentry_enabled = True
        logger.info(f"Sentry initialized (env={os.environ.get('ENV', 'development')})")

    except ImportError:
        logger.warning("sentry-sdk not installed. Run: pip install sentry-sdk")
    except Exception as e:
        logger.error(f"Sentry init failed: {e}")


def _before_send(event, hint):
    """Scrub sensitive data before sending to Sentry."""
    # Remove API keys from request headers
    if "request" in event:
        headers = event["request"].get("headers", {})
        for sensitive_key in ("x-api-key", "authorization", "cookie"):
            if sensitive_key in headers:
                headers[sensitive_key] = "[Filtered]"

    # Remove LLM API keys from extra data
    if "extra" in event:
        for key in list(event["extra"].keys()):
            if any(k in key.lower() for k in ("key", "token", "secret", "password")):
                event["extra"][key] = "[Filtered]"

    return event


def capture_exception(error: Exception, context: dict = None):
    """Capture exception to Sentry with optional context."""
    if not _sentry_enabled:
        return
    try:
        import sentry_sdk
        with sentry_sdk.push_scope() as scope:
            if context:
                for k, v in context.items():
                    scope.set_extra(k, v)
            sentry_sdk.capture_exception(error)
    except Exception:
        pass


def capture_message(message: str, level: str = "info", context: dict = None):
    """Send a message event to Sentry."""
    if not _sentry_enabled:
        return
    try:
        import sentry_sdk
        with sentry_sdk.push_scope() as scope:
            if context:
                for k, v in context.items():
                    scope.set_extra(k, v)
            sentry_sdk.capture_message(message, level=level)
    except Exception:
        pass


def set_user_context(domain: str):
    """Set user context (domain) for current request."""
    if not _sentry_enabled:
        return
    try:
        import sentry_sdk
        sentry_sdk.set_user({"id": domain, "domain": domain})
    except Exception:
        pass


def sentry_transaction(name: str, op: str = "task"):
    """Decorator to wrap a function in a Sentry performance transaction."""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            if not _sentry_enabled:
                return await func(*args, **kwargs)
            try:
                import sentry_sdk
                with sentry_sdk.start_transaction(name=name, op=op):
                    return await func(*args, **kwargs)
            except Exception:
                return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            if not _sentry_enabled:
                return func(*args, **kwargs)
            try:
                import sentry_sdk
                with sentry_sdk.start_transaction(name=name, op=op):
                    return func(*args, **kwargs)
            except Exception:
                return func(*args, **kwargs)

        import asyncio
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


def is_enabled() -> bool:
    return _sentry_enabled