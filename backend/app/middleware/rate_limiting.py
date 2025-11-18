"""
Rate Limiting Middleware for FastAPI
Implements multi-tier rate limiting with Redis-based sliding window algorithm
"""

import time
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple, List
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_429_TOO_MANY_REQUESTS

from app.core.config import settings
from app.core.cache import core_cache

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded"""
    def __init__(self, limit: int, remaining: int, reset: int, retry_after: int):
        self.limit = limit
        self.remaining = remaining
        self.reset = reset
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded. Retry after {retry_after} seconds")


class RateLimiter:
    """
    Redis-based rate limiter using sliding window algorithm

    The sliding window algorithm provides more accurate rate limiting than
    fixed windows by considering the timestamp of each request.
    """

    def __init__(self):
        self.enabled = getattr(settings, 'API_RATE_LIMITING_ENABLED', True)
        self.whitelist_ips = self._parse_whitelist()

    def _parse_whitelist(self) -> List[str]:
        """Parse IP whitelist from settings"""
        whitelist_str = getattr(settings, 'API_RATE_LIMIT_WHITELIST_IPS', '')
        if not whitelist_str:
            return ['127.0.0.1', '::1', 'localhost']  # Default localhost
        return [ip.strip() for ip in whitelist_str.split(',') if ip.strip()]

    async def check_rate_limit(
        self,
        identifier: str,
        limit_per_minute: int,
        limit_per_hour: int,
        prefix: str = "rate_limit"
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Check rate limit using sliding window algorithm

        Args:
            identifier: Unique identifier for the client (user_id, api_key_id, ip)
            limit_per_minute: Maximum requests per minute
            limit_per_hour: Maximum requests per hour
            prefix: Redis key prefix

        Returns:
            Tuple of (is_allowed, rate_limit_info)
        """
        if not self.enabled or not core_cache.enabled:
            # If rate limiting or Redis is disabled, allow all requests
            return True, {
                'limit_minute': limit_per_minute,
                'remaining_minute': limit_per_minute,
                'limit_hour': limit_per_hour,
                'remaining_hour': limit_per_hour,
                'reset_minute': int((datetime.utcnow() + timedelta(minutes=1)).timestamp()),
                'reset_hour': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
            }

        current_timestamp = time.time()
        minute_ago = current_timestamp - 60
        hour_ago = current_timestamp - 3600

        # Keys for minute and hour windows
        minute_key = f"{prefix}:minute:{identifier}"
        hour_key = f"{prefix}:hour:{identifier}"

        try:
            # Use Redis pipeline for atomic operations
            async with core_cache.pipeline() as pipe:
                if pipe is None:
                    # Pipeline not available, fallback to allowing request
                    logger.warning("Redis pipeline not available for rate limiting")
                    return True, self._default_rate_info(limit_per_minute, limit_per_hour)

                # Minute window operations
                # 1. Remove old entries from sorted set
                await pipe.zremrangebyscore(minute_key, 0, minute_ago)
                # 2. Count current entries
                await pipe.zcard(minute_key)
                # 3. Add current request
                await pipe.zadd(minute_key, {str(current_timestamp): current_timestamp})
                # 4. Set expiry (70 seconds to be safe)
                await pipe.expire(minute_key, 70)

                # Hour window operations
                await pipe.zremrangebyscore(hour_key, 0, hour_ago)
                await pipe.zcard(hour_key)
                await pipe.zadd(hour_key, {str(current_timestamp): current_timestamp})
                await pipe.expire(hour_key, 3700)

                # Execute pipeline
                results = await pipe.execute()

                # Parse results
                # results[1] is minute count before adding new request
                # results[5] is hour count before adding new request
                minute_count = results[1] if len(results) > 1 else 0
                hour_count = results[5] if len(results) > 5 else 0

                # Check limits (add 1 for current request)
                minute_exceeded = (minute_count + 1) > limit_per_minute
                hour_exceeded = (hour_count + 1) > limit_per_hour

                # Calculate remaining and reset times
                remaining_minute = max(0, limit_per_minute - minute_count - 1)
                remaining_hour = max(0, limit_per_hour - hour_count - 1)
                reset_minute = int(current_timestamp + 60)
                reset_hour = int(current_timestamp + 3600)

                rate_info = {
                    'limit_minute': limit_per_minute,
                    'remaining_minute': remaining_minute,
                    'limit_hour': limit_per_hour,
                    'remaining_hour': remaining_hour,
                    'reset_minute': reset_minute,
                    'reset_hour': reset_hour,
                    'current_minute_count': minute_count + 1,
                    'current_hour_count': hour_count + 1
                }

                if minute_exceeded or hour_exceeded:
                    # Determine which limit was exceeded and calculate retry_after
                    if minute_exceeded:
                        # Get oldest request in minute window to calculate exact retry time
                        oldest_in_minute = await core_cache.redis_client.zrange(
                            minute_key, 0, 0, withscores=True
                        )
                        if oldest_in_minute:
                            oldest_timestamp = oldest_in_minute[0][1]
                            retry_after = int(oldest_timestamp + 60 - current_timestamp) + 1
                        else:
                            retry_after = 60

                        logger.warning(
                            f"Rate limit exceeded (minute) - Identifier: {identifier}, "
                            f"Count: {minute_count + 1}/{limit_per_minute}, "
                            f"Retry after: {retry_after}s"
                        )
                    else:
                        # Hour limit exceeded
                        oldest_in_hour = await core_cache.redis_client.zrange(
                            hour_key, 0, 0, withscores=True
                        )
                        if oldest_in_hour:
                            oldest_timestamp = oldest_in_hour[0][1]
                            retry_after = int(oldest_timestamp + 3600 - current_timestamp) + 1
                        else:
                            retry_after = 3600

                        logger.warning(
                            f"Rate limit exceeded (hour) - Identifier: {identifier}, "
                            f"Count: {hour_count + 1}/{limit_per_hour}, "
                            f"Retry after: {retry_after}s"
                        )

                    rate_info['retry_after'] = retry_after
                    return False, rate_info

                return True, rate_info

        except Exception as e:
            logger.error(f"Rate limiting error for {identifier}: {e}", exc_info=True)
            # On error, allow the request but log it
            return True, self._default_rate_info(limit_per_minute, limit_per_hour)

    def _default_rate_info(self, limit_per_minute: int, limit_per_hour: int) -> Dict[str, Any]:
        """Return default rate info when Redis is unavailable"""
        current_time = datetime.utcnow()
        return {
            'limit_minute': limit_per_minute,
            'remaining_minute': limit_per_minute,
            'limit_hour': limit_per_hour,
            'remaining_hour': limit_per_hour,
            'reset_minute': int((current_time + timedelta(minutes=1)).timestamp()),
            'reset_hour': int((current_time + timedelta(hours=1)).timestamp())
        }

    def is_whitelisted(self, ip_address: str) -> bool:
        """Check if IP is whitelisted"""
        return ip_address in self.whitelist_ips


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Multi-tier rate limiting middleware

    Implements different rate limits based on:
    - Anonymous/unauthenticated users (IP-based, low limits)
    - Authenticated users (medium limits)
    - API key users (higher limits, can be customized per key)
    - Premium users (highest limits)
    """

    def __init__(self, app):
        super().__init__(app)
        self.limiter = RateLimiter()
        self.enabled = getattr(settings, 'API_RATE_LIMITING_ENABLED', True)

        # Rate limits for different tiers
        self.anonymous_limit_per_minute = getattr(
            settings, 'API_RATE_LIMIT_ANONYMOUS_PER_MINUTE', 10
        )
        self.anonymous_limit_per_hour = getattr(
            settings, 'API_RATE_LIMIT_ANONYMOUS_PER_HOUR', 100
        )
        self.authenticated_limit_per_minute = getattr(
            settings, 'API_RATE_LIMIT_AUTHENTICATED_PER_MINUTE', 20
        )
        self.authenticated_limit_per_hour = getattr(
            settings, 'API_RATE_LIMIT_AUTHENTICATED_PER_HOUR', 1200
        )
        self.api_key_limit_per_minute = getattr(
            settings, 'API_RATE_LIMIT_API_KEY_PER_MINUTE', 20
        )
        self.api_key_limit_per_hour = getattr(
            settings, 'API_RATE_LIMIT_API_KEY_PER_HOUR', 1200
        )
        self.premium_limit_per_minute = getattr(
            settings, 'API_RATE_LIMIT_PREMIUM_PER_MINUTE', 20
        )
        self.premium_limit_per_hour = getattr(
            settings, 'API_RATE_LIMIT_PREMIUM_PER_HOUR', 1200
        )

        logger.info(
            f"Rate limiting middleware initialized - "
            f"Enabled: {self.enabled}, "
            f"Anonymous: {self.anonymous_limit_per_minute}/min {self.anonymous_limit_per_hour}/hr, "
            f"Authenticated: {self.authenticated_limit_per_minute}/min {self.authenticated_limit_per_hour}/hr, "
            f"API Key: {self.api_key_limit_per_minute}/min {self.api_key_limit_per_hour}/hr, "
            f"Premium: {self.premium_limit_per_minute}/min {self.premium_limit_per_hour}/hr"
        )

    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting"""

        # Skip rate limiting for certain paths
        if self._should_skip_rate_limit(request):
            return await call_next(request)

        # Skip if rate limiting is disabled
        if not self.enabled:
            return await call_next(request)

        # Get client IP
        client_ip = self._get_client_ip(request)

        # Check if IP is whitelisted
        if self.limiter.is_whitelisted(client_ip):
            logger.debug(f"IP {client_ip} is whitelisted, skipping rate limit")
            return await call_next(request)

        # Determine user type and get rate limits
        identifier, limit_per_minute, limit_per_hour, user_type = await self._get_rate_limits(
            request, client_ip
        )

        # Check rate limit
        allowed, rate_info = await self.limiter.check_rate_limit(
            identifier=identifier,
            limit_per_minute=limit_per_minute,
            limit_per_hour=limit_per_hour,
            prefix="api_rate_limit"
        )

        # Add rate limit headers to response
        if not allowed:
            # Rate limit exceeded
            retry_after = rate_info.get('retry_after', 60)

            logger.warning(
                f"Rate limit exceeded for {user_type} - "
                f"Identifier: {identifier}, "
                f"IP: {client_ip}, "
                f"Path: {request.url.path}, "
                f"Retry after: {retry_after}s"
            )

            return JSONResponse(
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": "Rate limit exceeded. Please try again later.",
                    "details": {
                        "limit_per_minute": rate_info['limit_minute'],
                        "limit_per_hour": rate_info['limit_hour'],
                        "retry_after": retry_after
                    }
                },
                headers={
                    "X-RateLimit-Limit-Minute": str(rate_info['limit_minute']),
                    "X-RateLimit-Remaining-Minute": "0",
                    "X-RateLimit-Reset-Minute": str(rate_info['reset_minute']),
                    "X-RateLimit-Limit-Hour": str(rate_info['limit_hour']),
                    "X-RateLimit-Remaining-Hour": "0",
                    "X-RateLimit-Reset-Hour": str(rate_info['reset_hour']),
                    "Retry-After": str(retry_after)
                }
            )

        # Process request
        response = await call_next(request)

        # Add rate limit headers to successful response
        response.headers["X-RateLimit-Limit-Minute"] = str(rate_info['limit_minute'])
        response.headers["X-RateLimit-Remaining-Minute"] = str(rate_info['remaining_minute'])
        response.headers["X-RateLimit-Reset-Minute"] = str(rate_info['reset_minute'])
        response.headers["X-RateLimit-Limit-Hour"] = str(rate_info['limit_hour'])
        response.headers["X-RateLimit-Remaining-Hour"] = str(rate_info['remaining_hour'])
        response.headers["X-RateLimit-Reset-Hour"] = str(rate_info['reset_hour'])

        return response

    def _should_skip_rate_limit(self, request: Request) -> bool:
        """Determine if rate limiting should be skipped for this request"""
        # Skip health checks and docs
        skip_paths = [
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/api/v1/docs",
            "/api/v1/redoc",
            "/api/v1/openapi.json",
            "/api-internal/v1/docs",
            "/api-internal/v1/redoc",
            "/api-internal/v1/openapi.json"
        ]

        path = request.url.path

        # Skip exact matches
        if path in skip_paths:
            return True

        # Skip static files
        if path.startswith("/static"):
            return True

        return False

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Check X-Forwarded-For header (for proxied requests)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain
            return forwarded_for.split(",")[0].strip()

        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fallback to client host
        if request.client:
            return request.client.host

        return "unknown"

    async def _get_rate_limits(
        self,
        request: Request,
        client_ip: str
    ) -> Tuple[str, int, int, str]:
        """
        Determine rate limits based on authentication type

        Returns:
            Tuple of (identifier, limit_per_minute, limit_per_hour, user_type)
        """
        # Try to get API key first
        api_key = self._extract_api_key(request)

        if api_key:
            # API key authentication
            api_key_info = await self._get_api_key_info(api_key, request)
            if api_key_info:
                api_key_obj = api_key_info.get('api_key')
                user = api_key_info.get('user')

                # Use custom rate limits from API key if available
                limit_per_minute = getattr(
                    api_key_obj, 'rate_limit_per_minute', self.api_key_limit_per_minute
                )
                limit_per_hour = getattr(
                    api_key_obj, 'rate_limit_per_hour', self.api_key_limit_per_hour
                )

                # Check if user is premium (has higher limits)
                # You can customize this logic based on your user tier system
                if user and hasattr(user, 'role'):
                    if user.role == 'premium' or user.role == 'super_admin':
                        limit_per_minute = max(limit_per_minute, self.premium_limit_per_minute)
                        limit_per_hour = max(limit_per_hour, self.premium_limit_per_hour)
                        user_type = "premium_api_key"
                    else:
                        user_type = "api_key"
                else:
                    user_type = "api_key"

                # Use API key ID as identifier for rate limiting
                identifier = f"api_key:{api_key_obj.id}"

                logger.debug(
                    f"Rate limit for {user_type} - "
                    f"API Key ID: {api_key_obj.id}, "
                    f"Limits: {limit_per_minute}/min, {limit_per_hour}/hr"
                )

                return identifier, limit_per_minute, limit_per_hour, user_type

        # Try JWT authentication
        jwt_token = self._extract_jwt_token(request)

        if jwt_token:
            user_info = await self._get_user_from_token(jwt_token)
            if user_info:
                user_id = user_info.get('id')
                user_role = user_info.get('role', 'user')

                # Check if premium user
                if user_role == 'premium' or user_role == 'super_admin':
                    limit_per_minute = self.premium_limit_per_minute
                    limit_per_hour = self.premium_limit_per_hour
                    user_type = "premium_user"
                else:
                    limit_per_minute = self.authenticated_limit_per_minute
                    limit_per_hour = self.authenticated_limit_per_hour
                    user_type = "authenticated_user"

                identifier = f"user:{user_id}"

                logger.debug(
                    f"Rate limit for {user_type} - "
                    f"User ID: {user_id}, "
                    f"Limits: {limit_per_minute}/min, {limit_per_hour}/hr"
                )

                return identifier, limit_per_minute, limit_per_hour, user_type

        # Default to anonymous (IP-based)
        identifier = f"ip:{client_ip}"
        user_type = "anonymous"

        logger.debug(
            f"Rate limit for {user_type} - "
            f"IP: {client_ip}, "
            f"Limits: {self.anonymous_limit_per_minute}/min, {self.anonymous_limit_per_hour}/hr"
        )

        return (
            identifier,
            self.anonymous_limit_per_minute,
            self.anonymous_limit_per_hour,
            user_type
        )

    def _extract_api_key(self, request: Request) -> Optional[str]:
        """Extract API key from request"""
        # Check Authorization header with Bearer
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            # Check if it's an API key (starts with API_KEY_PREFIX)
            if token.startswith(settings.API_KEY_PREFIX):
                return token

        # Check X-API-Key header
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return api_key

        # Check query parameter
        api_key = request.query_params.get("api_key")
        if api_key:
            return api_key

        return None

    def _extract_jwt_token(self, request: Request) -> Optional[str]:
        """Extract JWT token from request"""
        # Check Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            # Make sure it's not an API key
            if not token.startswith(settings.API_KEY_PREFIX):
                return token

        return None

    async def _get_api_key_info(
        self,
        api_key: str,
        request: Request
    ) -> Optional[Dict[str, Any]]:
        """Get API key information from cache or database"""
        try:
            # Import here to avoid circular imports
            from app.services.cached_api_key import cached_api_key_service
            from app.db.database import async_session_factory

            # Extract key prefix
            if len(api_key) < 8:
                return None

            key_prefix = api_key[:8]

            # Get from cache or database
            async with async_session_factory() as db:
                context = await cached_api_key_service.get_cached_api_key(key_prefix, db)
                if context:
                    api_key_obj = context.get('api_key')
                    # Verify key is active and valid
                    if api_key_obj and api_key_obj.is_valid():
                        return context
        except Exception as e:
            logger.error(f"Error getting API key info: {e}")

        return None

    async def _get_user_from_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Get user information from JWT token"""
        try:
            from app.core.security import verify_token

            payload = verify_token(token)
            user_id = payload.get("sub")

            if user_id:
                return {
                    'id': int(user_id),
                    'role': payload.get('role', 'user'),
                    'email': payload.get('email')
                }
        except Exception as e:
            logger.debug(f"Failed to verify JWT token: {e}")

        return None


def setup_rate_limiting_middleware(app):
    """Add rate limiting middleware to the FastAPI app"""
    enabled = getattr(settings, 'API_RATE_LIMITING_ENABLED', True)

    if enabled:
        app.add_middleware(RateLimitMiddleware)
        logger.info("Rate limiting middleware enabled and configured")
    else:
        logger.info("Rate limiting middleware is disabled")
