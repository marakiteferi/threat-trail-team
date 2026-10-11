import io
import json
import logging
import os
import time
import zipfile
from collections import defaultdict
from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("threattrail.security")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", 10 * 1024 * 1024))  # 10 MB
MAX_EXTRACTED_BYTES = 25 * 1024 * 1024  # 25 MB Zip-Bomb ceiling


def validate_required_env() -> None:
    """Fail fast with a clear message if critical environment variables are missing."""
    secret = os.getenv("JWT_SECRET_KEY", "")
    if not secret or secret == "REPLACE_WITH_32_BYTE_HEX_SECRET_KEY_BEFORE_RUNNING" or len(secret) < 16:
        raise RuntimeError(
            "CRITICAL CONFIG ERROR: JWT_SECRET_KEY is missing or weak. "
            "Copy .env.example to .env and set a strong JWT_SECRET_KEY (e.g. `openssl rand -hex 32`)."
        )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' http://localhost:5050 http://127.0.0.1:5050; "
            "frame-ancestors 'none';"
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 20, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self.hits: dict[str, list[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if request.method == "POST" and ("/login" in path or "/submit" in path):
            client_ip = request.client.host if request.client else "unknown"
            key = f"{client_ip}:{path}"
            now = time.time()
            self.hits[key] = [t for t in self.hits[key] if now - t < self.window]
            if len(self.hits[key]) >= self.max_requests:
                logger.warning("Rate limit exceeded for %s on %s", client_ip, path)
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Too many attempts. Please wait a minute and try again."},
                )
            self.hits[key].append(now)
        return await call_next(request)


def register_security_hardening(app: FastAPI) -> None:
    origins = [
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
        if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, max_requests=15, window_seconds=60)

    @app.exception_handler(Exception)
    async def safe_global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled error on %s: %s", request.url.path, type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal server error occurred. Please try again."},
        )


async def validate_and_extract_log_upload(upload: UploadFile) -> list[dict]:
    """Safely parse uploaded .json or .zip Windows Event log files with Zip-Bomb & Zip-Slip guards."""
    raw_bytes = await upload.read(MAX_UPLOAD_BYTES + 1)
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Uploaded file exceeds 10 MB limit.")

    filename = (upload.filename or "").lower()
    if filename.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            total_uncompressed = sum(info.file_size for info in zf.infolist())
            if total_uncompressed > MAX_EXTRACTED_BYTES:
                raise HTTPException(status_code=400, detail="Archive exceeds safe uncompressed size limit.")
            for info in zf.infolist():
                if ".." in info.filename or info.filename.startswith("/"):
                    raise HTTPException(status_code=400, detail="Unsafe path detected in archive.")
                if info.filename.lower().endswith(".json"):
                    raw_bytes = zf.read(info.filename)
                    break
            else:
                raise HTTPException(status_code=400, detail="No .json log file found inside archive.")
    elif not filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only .json or .zip log files are supported.")

    text = raw_bytes.decode("utf-8", errors="replace").strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        # Support JSON-Lines (NDJSON) used by Mordor datasets
        events = []
        for line in text.splitlines():
            if line.strip():
                events.append(json.loads(line))
        return events
