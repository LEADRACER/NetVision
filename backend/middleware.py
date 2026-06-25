"""FastAPI middleware: request ID correlation + access logging + audit trail."""

import uuid
import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from logging_setup import request_id_var
from loguru import logger


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject X-Request-ID into every request and set context var for logging.

    Also records an audit trail entry for every API call via the Database instance.
    """

    def __init__(self, app, db=None):
        super().__init__(app)
        self.db = db

    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request_id_var.set(req_id)

        start = time.monotonic()

        response: Response = await call_next(request)

        elapsed_ms = (time.monotonic() - start) * 1000
        response.headers["X-Request-ID"] = req_id

        path = request.url.path

        # Skip logging for static files and metrics to avoid noise
        skip_paths = {"/metrics", "/health", "/health/live"}
        if path in skip_paths:
            return response

        # Access log
        logger.info(
            f"{request.method} {path} -> {response.status_code} ({elapsed_ms:.1f}ms)",
            extra={
                "component": "api",
                "request_id": req_id,
                "method": request.method,
                "path": path,
                "status": response.status_code,
                "elapsed_ms": round(elapsed_ms, 1),
                "client_ip": request.client.host if request.client else "unknown",
            },
        )

        # Audit trail — async write to DB
        if self.db and path not in ("/ws",):
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                loop.run_in_executor(
                    None,
                    self.db.record_audit,
                    request.method,
                    path,
                    response.status_code,
                    request.client.host if request.client else "",
                    req_id,
                    request.headers.get("User-Agent", "")[:200],
                    round(elapsed_ms, 1),
                    "",
                )
            except Exception:
                pass

        return response
