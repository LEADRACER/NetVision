"""FastAPI middleware: request ID correlation + access logging."""

import uuid
import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from logging_setup import request_id_var
from loguru import logger


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject X-Request-ID into every request and set context var for logging."""

    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request_id_var.set(req_id)

        start = time.monotonic()

        response: Response = await call_next(request)

        elapsed_ms = (time.monotonic() - start) * 1000
        response.headers["X-Request-ID"] = req_id

        # Access log
        logger.info(
            f"{request.method} {request.url.path} -> {response.status_code} ({elapsed_ms:.1f}ms)",
            extra={
                "component": "api",
                "request_id": req_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "elapsed_ms": round(elapsed_ms, 1),
                "client_ip": request.client.host if request.client else "unknown",
            },
        )

        return response
