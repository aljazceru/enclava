"""
Request validation middleware for FastAPI application

This module provides comprehensive request validation including:
- Request body size limits
- Content-Type validation
- Header validation
- Input sanitization
"""

import logging
import re
from typing import Callable, List, Optional, Set
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate incoming requests

    - Enforces request size limits based on user tier
    - Validates Content-Type headers
    - Validates required headers
    - Sanitizes input to prevent injection attacks
    """

    # Allowed Content-Types for POST/PUT/PATCH requests
    ALLOWED_CONTENT_TYPES: Set[str] = {
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
    }

    # Paths that should skip validation
    SKIP_VALIDATION_PATHS: Set[str] = {
        "/health",
        "/",
        "/api/v1/docs",
        "/api/v1/openapi.json",
        "/api/v1/redoc",
        "/api-internal/v1/docs",
        "/api-internal/v1/openapi.json",
        "/api-internal/v1/redoc",
    }

    # Suspicious patterns that might indicate injection attempts
    SUSPICIOUS_PATTERNS: List[re.Pattern] = [
        re.compile(r"<script[^>]*>", re.IGNORECASE),  # XSS attempts
        re.compile(r"javascript:", re.IGNORECASE),  # JavaScript protocol
        re.compile(r"on\w+\s*=", re.IGNORECASE),  # Event handlers
        re.compile(r"eval\(", re.IGNORECASE),  # Eval attempts
        re.compile(r"union\s+select", re.IGNORECASE),  # SQL injection
        re.compile(r";\s*drop\s+table", re.IGNORECASE),  # SQL injection
        re.compile(r"--\s*$", re.MULTILINE),  # SQL comments
        re.compile(r"\.\./", re.IGNORECASE),  # Path traversal
        re.compile(r"\.\.\\", re.IGNORECASE),  # Path traversal (Windows)
    ]

    def __init__(self, app: ASGIApp, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled and settings.API_REQUEST_VALIDATION_ENABLED
        logger.info(f"RequestValidationMiddleware initialized, enabled: {self.enabled}")

    def _should_skip_validation(self, request: Request) -> bool:
        """Check if request should skip validation"""
        # Skip validation for specific paths
        if request.url.path in self.SKIP_VALIDATION_PATHS:
            return True

        # Skip validation for GET and DELETE requests (no body)
        if request.method in ["GET", "DELETE", "HEAD", "OPTIONS"]:
            return True

        return False

    def _get_max_request_size(self, request: Request) -> int:
        """Get maximum allowed request size based on user tier"""
        # Check if user has premium tier (stored in request state by auth middleware)
        user = getattr(request.state, "user", None)
        if user and getattr(user, "is_premium", False):
            return settings.API_MAX_REQUEST_BODY_SIZE_PREMIUM

        # Default to standard size limit
        return settings.API_MAX_REQUEST_BODY_SIZE

    async def _check_request_size(self, request: Request) -> Optional[JSONResponse]:
        """Check if request body size is within limits"""
        max_size = self._get_max_request_size(request)

        # Check Content-Length header
        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                size = int(content_length)
                if size > max_size:
                    logger.warning(
                        f"Request body too large: {size} bytes (max: {max_size}), "
                        f"path: {request.url.path}, method: {request.method}"
                    )
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "REQUEST_TOO_LARGE",
                            "message": f"Request body too large. Maximum size: {max_size} bytes",
                            "max_size_bytes": max_size,
                        }
                    )
            except ValueError:
                # Invalid Content-Length header
                logger.warning(
                    f"Invalid Content-Length header: {content_length}, "
                    f"path: {request.url.path}"
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "INVALID_HEADER",
                        "message": "Invalid Content-Length header"
                    }
                )

        return None

    def _validate_content_type(self, request: Request) -> Optional[JSONResponse]:
        """Validate Content-Type header for requests with body"""
        content_type = request.headers.get("Content-Type")

        if not content_type:
            logger.warning(
                f"Missing Content-Type header, "
                f"path: {request.url.path}, method: {request.method}"
            )
            return JSONResponse(
                status_code=400,
                content={
                    "error": "MISSING_CONTENT_TYPE",
                    "message": "Content-Type header is required",
                    "allowed_types": list(self.ALLOWED_CONTENT_TYPES),
                }
            )

        # Extract base content type (ignore charset and other parameters)
        base_content_type = content_type.split(";")[0].strip().lower()

        # Check if content type is allowed
        is_allowed = any(
            base_content_type == allowed or base_content_type.startswith(allowed)
            for allowed in self.ALLOWED_CONTENT_TYPES
        )

        if not is_allowed:
            logger.warning(
                f"Invalid Content-Type: {content_type}, "
                f"path: {request.url.path}, method: {request.method}"
            )
            return JSONResponse(
                status_code=415,
                content={
                    "error": "UNSUPPORTED_MEDIA_TYPE",
                    "message": f"Unsupported Content-Type: {content_type}",
                    "allowed_types": list(self.ALLOWED_CONTENT_TYPES),
                }
            )

        return None

    def _check_suspicious_headers(self, request: Request) -> Optional[JSONResponse]:
        """Check for suspicious patterns in headers"""
        for header_name, header_value in request.headers.items():
            # Skip validation for common headers that might contain special chars
            if header_name.lower() in ["user-agent", "accept", "accept-language"]:
                continue

            # Check for suspicious patterns
            for pattern in self.SUSPICIOUS_PATTERNS:
                if pattern.search(header_value):
                    logger.warning(
                        f"Suspicious pattern in header: {header_name}, "
                        f"pattern: {pattern.pattern}, "
                        f"path: {request.url.path}, method: {request.method}"
                    )
                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": "INVALID_REQUEST",
                            "message": "Invalid request: suspicious content detected in headers"
                        }
                    )

        return None

    def _check_suspicious_url(self, request: Request) -> Optional[JSONResponse]:
        """Check for suspicious patterns in URL"""
        url_path = str(request.url.path)
        query_string = str(request.url.query)

        # Check path for suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.search(url_path):
                logger.warning(
                    f"Suspicious pattern in URL path, "
                    f"pattern: {pattern.pattern}, "
                    f"path: {request.url.path}, method: {request.method}"
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "INVALID_REQUEST",
                        "message": "Invalid request: suspicious content detected in URL"
                    }
                )

            # Check query string
            if query_string and pattern.search(query_string):
                logger.warning(
                    f"Suspicious pattern in query string, "
                    f"pattern: {pattern.pattern}, "
                    f"path: {request.url.path}, method: {request.method}"
                )
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "INVALID_REQUEST",
                        "message": "Invalid request: suspicious content detected in query parameters"
                    }
                )

        return None

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Validate incoming requests"""
        if not self.enabled:
            return await call_next(request)

        # Skip validation for certain requests
        if self._should_skip_validation(request):
            return await call_next(request)

        # Check request size
        error_response = await self._check_request_size(request)
        if error_response:
            return error_response

        # Validate Content-Type for requests with body
        if request.method in ["POST", "PUT", "PATCH"]:
            error_response = self._validate_content_type(request)
            if error_response:
                return error_response

        # Check for suspicious patterns in headers
        error_response = self._check_suspicious_headers(request)
        if error_response:
            return error_response

        # Check for suspicious patterns in URL
        error_response = self._check_suspicious_url(request)
        if error_response:
            return error_response

        # All validations passed, continue with request
        return await call_next(request)


def setup_request_validation_middleware(app: ASGIApp, enabled: bool = True) -> None:
    """
    Setup request validation middleware for the application

    Args:
        app: FastAPI application instance
        enabled: Whether request validation middleware is enabled
    """
    overall_enabled = enabled and settings.API_REQUEST_VALIDATION_ENABLED

    logger.info(f"Setting up request validation middleware, enabled: {overall_enabled}")

    app.add_middleware(RequestValidationMiddleware, enabled=overall_enabled)

    logger.info("Request validation middleware setup complete")
