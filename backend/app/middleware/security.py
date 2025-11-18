"""
Security middleware for FastAPI application

This module provides comprehensive security middleware including:
- Request ID tracking
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- IP filtering and blocking
- Error sanitization
"""

import logging
import uuid
from typing import Callable, List, Optional
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add unique request ID to each request

    - Adds X-Request-ID header to all requests and responses
    - Includes request ID in logs for traceability
    - Can use client-provided request ID or generate new one
    """

    def __init__(self, app: ASGIApp, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
        logger.info(f"RequestIDMiddleware initialized, enabled: {self.enabled}")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add request ID to request and response"""
        if not self.enabled:
            return await call_next(request)

        # Check if client provided a request ID, otherwise generate one
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid.uuid4())

        # Store request ID in request state for use in other middleware/handlers
        request.state.request_id = request_id

        # Process request
        response = await call_next(request)

        # Add request ID to response headers
        response.headers["X-Request-ID"] = request_id

        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses

    Headers added:
    - Content-Security-Policy (CSP)
    - X-Frame-Options (prevents clickjacking)
    - X-Content-Type-Options (prevents MIME sniffing)
    - Strict-Transport-Security (HSTS - forces HTTPS)
    - X-XSS-Protection (XSS filtering)
    - Referrer-Policy (controls referrer information)
    - Permissions-Policy (controls browser features)
    """

    def __init__(self, app: ASGIApp, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled and settings.API_SECURITY_HEADERS_ENABLED
        logger.info(f"SecurityHeadersMiddleware initialized, enabled: {self.enabled}")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers to response"""
        response = await call_next(request)

        if not self.enabled:
            return response

        # Content Security Policy - prevents XSS and injection attacks
        response.headers["Content-Security-Policy"] = settings.API_CSP_HEADER

        # Prevent clickjacking attacks
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Force HTTPS (only for production, 1 year max-age)
        # Note: Only added if request came over HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Enable XSS filtering in browsers
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Control browser features and APIs
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )

        return response


class IPFilterMiddleware(BaseHTTPMiddleware):
    """
    Middleware to filter requests based on IP addresses

    - Block requests from blacklisted IPs
    - Allow only whitelisted IPs (if whitelist is configured)
    - Logs blocked requests
    """

    def __init__(self, app: ASGIApp, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled and settings.API_SECURITY_ENABLED

        # Parse blocked IPs from comma-separated string
        self.blocked_ips: List[str] = []
        if settings.API_BLOCKED_IPS:
            self.blocked_ips = [ip.strip() for ip in settings.API_BLOCKED_IPS.split(",") if ip.strip()]

        # Parse allowed IPs from comma-separated string
        self.allowed_ips: List[str] = []
        if settings.API_ALLOWED_IPS:
            self.allowed_ips = [ip.strip() for ip in settings.API_ALLOWED_IPS.split(",") if ip.strip()]

        logger.info(
            f"IPFilterMiddleware initialized, enabled: {self.enabled}, "
            f"blocked_ips: {len(self.blocked_ips)}, allowed_ips: {len(self.allowed_ips)}"
        )

    def _get_client_ip(self, request: Request) -> Optional[str]:
        """Get client IP from request, considering proxies"""
        # Check X-Forwarded-For header (from proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # X-Forwarded-For can contain multiple IPs, take the first one
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP header (from proxy)
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fall back to direct client IP
        if request.client:
            return request.client.host

        return None

    def _is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        if not ip:
            return False

        # Check if IP is in blocklist
        if ip in self.blocked_ips:
            return True

        # If allowlist is configured and IP is not in it, block
        if self.allowed_ips and ip not in self.allowed_ips:
            return True

        return False

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Filter requests based on IP"""
        if not self.enabled:
            return await call_next(request)

        # Get client IP
        client_ip = self._get_client_ip(request)

        # Check if IP should be blocked
        if client_ip and self._is_ip_blocked(client_ip):
            logger.warning(
                f"Blocked request from IP: {client_ip}, "
                f"path: {request.url.path}, method: {request.method}"
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "FORBIDDEN",
                    "message": "Access denied"
                }
            )

        # Store client IP in request state
        request.state.client_ip = client_ip

        return await call_next(request)


class ErrorSanitizationMiddleware(BaseHTTPMiddleware):
    """
    Middleware to sanitize error responses

    - Prevents leaking sensitive information in error messages
    - Ensures consistent error response format
    - Logs detailed errors internally while showing safe messages to clients
    """

    def __init__(self, app: ASGIApp, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled and settings.API_SECURITY_ENABLED
        logger.info(f"ErrorSanitizationMiddleware initialized, enabled: {self.enabled}")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Sanitize errors in responses"""
        try:
            response = await call_next(request)
            return response
        except Exception as exc:
            if not self.enabled:
                # Re-raise if middleware is disabled
                raise

            # Log the full error internally
            request_id = getattr(request.state, "request_id", "unknown")
            logger.error(
                f"Request error: {type(exc).__name__}: {str(exc)}, "
                f"request_id: {request_id}, "
                f"path: {request.url.path}, "
                f"method: {request.method}",
                exc_info=True
            )

            # Return sanitized error response
            # Don't leak internal error details to clients
            return JSONResponse(
                status_code=500,
                content={
                    "error": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected error occurred. Please try again later.",
                    "request_id": request_id
                }
            )


def setup_security_middleware(app: ASGIApp, enabled: bool = True) -> None:
    """
    Setup all security middleware for the application

    Args:
        app: FastAPI application instance
        enabled: Whether security middleware is enabled (can be overridden by individual settings)
    """
    overall_enabled = enabled and settings.API_SECURITY_ENABLED

    logger.info(f"Setting up security middleware, overall_enabled: {overall_enabled}")

    # Add middleware in reverse order (they will be executed in the order added)
    # Last added = first executed

    # 1. Error sanitization (innermost - catches errors from all other middleware)
    app.add_middleware(ErrorSanitizationMiddleware, enabled=overall_enabled)

    # 2. IP filtering (early filtering of blocked IPs)
    app.add_middleware(IPFilterMiddleware, enabled=overall_enabled)

    # 3. Security headers (add headers to all responses)
    app.add_middleware(SecurityHeadersMiddleware, enabled=overall_enabled)

    # 4. Request ID (outermost - tracks all requests)
    app.add_middleware(RequestIDMiddleware, enabled=overall_enabled)

    logger.info("Security middleware setup complete")
