# Rate Limiting Middleware

## Overview

The rate limiting middleware implements comprehensive, multi-tier rate limiting for the FastAPI backend using Redis-based sliding window algorithm for accurate request tracking.

## Features

### 1. Multi-Tier Rate Limiting

The middleware supports different rate limit tiers based on user authentication type:

- **Anonymous/Unauthenticated Users** (IP-based)
  - Lowest limits for users without authentication
  - Tracked by IP address
  - Default: 10 req/min, 100 req/hour

- **Authenticated Users** (JWT-based)
  - Medium limits for users authenticated via JWT
  - Tracked by user ID
  - Default: 20 req/min, 1200 req/hour

- **API Key Users**
  - Higher limits for programmatic access
  - Tracked by API key ID
  - Supports per-API-key custom limits
  - Default: 20 req/min, 1200 req/hour

- **Premium Users**
  - Highest limits for premium/enterprise users
  - Automatically detected based on user role
  - Default: 20 req/min, 1200 req/hour

### 2. Sliding Window Algorithm

The middleware uses a Redis-based sliding window algorithm that:
- Provides more accurate rate limiting than fixed windows
- Tracks exact timestamps of requests
- Automatically expires old entries
- Calculates precise retry-after times

### 3. Per-API-Key Custom Limits

API keys can have custom rate limits stored in the database:
- `rate_limit_per_minute`: Custom requests per minute
- `rate_limit_per_hour`: Custom requests per hour
- `rate_limit_per_day`: Custom requests per day (not yet implemented in middleware)

These override the default tier limits.

### 4. Rate Limit Headers

The middleware adds standard rate limit headers to all responses:

```
X-RateLimit-Limit-Minute: 60
X-RateLimit-Remaining-Minute: 45
X-RateLimit-Reset-Minute: 1700000000

X-RateLimit-Limit-Hour: 3600
X-RateLimit-Remaining-Hour: 3555
X-RateLimit-Reset-Hour: 1700003600
```

When rate limit is exceeded:
```
Retry-After: 30
```

### 5. IP Whitelisting

Certain IPs can bypass rate limiting:
- Configured via `API_RATE_LIMIT_WHITELIST_IPS` environment variable
- Comma-separated list of IPs
- Default: `127.0.0.1,::1` (localhost)

### 6. Smart Path Skipping

The middleware automatically skips rate limiting for:
- Health check endpoints (`/health`)
- API documentation (`/docs`, `/redoc`, `/openapi.json`)
- Static files (`/static/*`)

## Configuration

### Environment Variables

```bash
# Enable/disable rate limiting
API_RATE_LIMITING_ENABLED=true

# IP whitelist (comma-separated)
API_RATE_LIMIT_WHITELIST_IPS=127.0.0.1,::1,10.0.0.1

# Anonymous users
API_RATE_LIMIT_ANONYMOUS_PER_MINUTE=10
API_RATE_LIMIT_ANONYMOUS_PER_HOUR=100

# Authenticated users
API_RATE_LIMIT_AUTHENTICATED_PER_MINUTE=20
API_RATE_LIMIT_AUTHENTICATED_PER_HOUR=1200

# API key users
API_RATE_LIMIT_API_KEY_PER_MINUTE=20
API_RATE_LIMIT_API_KEY_PER_HOUR=1200

# Premium users
API_RATE_LIMIT_PREMIUM_PER_MINUTE=20
API_RATE_LIMIT_PREMIUM_PER_HOUR=1200
```

### Database Configuration (API Keys)

Individual API keys can override default limits:

```python
api_key = APIKey(
    name="My Custom API Key",
    rate_limit_per_minute=100,  # Custom limit
    rate_limit_per_hour=6000,   # Custom limit
    # ... other fields
)
```

## Usage

The middleware is automatically registered in `main.py`:

```python
from app.middleware.rate_limiting import setup_rate_limiting_middleware
setup_rate_limiting_middleware(app)
```

## Architecture

### Components

1. **RateLimiter Class**
   - Implements sliding window algorithm
   - Manages Redis operations
   - Handles IP whitelisting

2. **RateLimitMiddleware Class**
   - FastAPI middleware integration
   - Authentication detection
   - Header management
   - Error responses

### Redis Data Structure

The middleware uses Redis Sorted Sets for efficient sliding window tracking:

```
Key: api_rate_limit:minute:{identifier}
Type: Sorted Set
Members: timestamp strings
Scores: timestamp values
TTL: 70 seconds

Key: api_rate_limit:hour:{identifier}
Type: Sorted Set
Members: timestamp strings
Scores: timestamp values
TTL: 3700 seconds
```

### Authentication Flow

1. **Extract credentials from request**
   - Check for API key (Authorization header, X-API-Key header, query param)
   - Check for JWT token (Authorization header)
   - Fallback to IP-based anonymous

2. **Determine rate limits**
   - API key: Use custom limits or default API key tier
   - JWT: Check user role (premium vs standard)
   - Anonymous: Use IP-based limits

3. **Check rate limit**
   - Query Redis using sliding window
   - Calculate remaining requests
   - Determine if limit exceeded

4. **Handle response**
   - If allowed: Add headers and continue
   - If exceeded: Return 429 with retry-after

## Error Handling

The middleware includes comprehensive error handling:

- **Redis unavailable**: Allows requests but logs errors
- **Database errors**: Allows requests but logs errors
- **Authentication errors**: Treats as anonymous user
- **Pipeline errors**: Allows requests but logs errors

This ensures the API remains available even if rate limiting fails.

## Performance

### Optimizations

1. **Redis Pipeline**: Atomic operations reduce round trips
2. **Caching**: API key info cached in Redis
3. **Early exits**: Whitelisted IPs and skipped paths bypass all logic
4. **Efficient queries**: Sorted sets provide O(log N) operations

### Redis Load

For 1000 requests/second:
- ~2000 Redis operations/second (read + write for minute + hour windows)
- ~4KB/request in Redis memory
- Automatic cleanup via TTL

## Monitoring

### Logging

The middleware logs:
- Rate limit exceeded events (WARNING level)
- Configuration on startup (INFO level)
- Errors (ERROR level)
- Debug info when enabled (DEBUG level)

### Metrics

Track these metrics for monitoring:
- Rate limit exceeded count by tier
- Average remaining requests by tier
- Redis errors
- Authentication type distribution

## Testing

### Manual Testing

```bash
# Test anonymous user (no auth)
curl -v http://localhost:8000/api/v1/some-endpoint

# Test with API key
curl -v -H "X-API-Key: en_your_api_key" http://localhost:8000/api/v1/some-endpoint

# Test with JWT
curl -v -H "Authorization: Bearer your_jwt_token" http://localhost:8000/api/v1/some-endpoint

# Check headers
curl -v http://localhost:8000/api/v1/some-endpoint 2>&1 | grep -i "X-RateLimit"
```

### Exceeding Limits

```bash
# Quick script to test rate limiting
for i in {1..15}; do
  echo "Request $i:"
  curl -v http://localhost:8000/api/v1/some-endpoint 2>&1 | grep -E "(HTTP|X-RateLimit|Retry-After)"
  echo "---"
done
```

## Troubleshooting

### Rate limits not working

1. Check `API_RATE_LIMITING_ENABLED=true` in .env
2. Verify Redis is running: `redis-cli ping`
3. Check logs for errors
4. Verify IP is not whitelisted

### All requests getting rate limited

1. Check Redis for stuck data: `redis-cli KEYS "api_rate_limit:*"`
2. Clear Redis if needed: `redis-cli FLUSHDB`
3. Check system clock sync
4. Verify rate limits are not too low

### Headers not appearing

1. Check middleware is registered in main.py
2. Verify middleware order (should be before security middleware)
3. Check for CORS issues
4. Verify endpoint is not skipped

## Future Enhancements

Potential improvements:

1. **Per-endpoint rate limits**: Different limits for different endpoints
2. **Burst allowance**: Allow short bursts above normal limits
3. **Distributed rate limiting**: Coordinate across multiple instances
4. **Cost-based limiting**: Limit based on computational cost, not just count
5. **Dynamic limits**: Adjust limits based on system load
6. **GraphQL support**: Field-level rate limiting
7. **WebSocket support**: Connection-based rate limiting

## Security Considerations

1. **IP spoofing**: Use X-Forwarded-For carefully, validate proxy chain
2. **Token theft**: Rate limits don't prevent, combine with other security
3. **DDoS**: Rate limiting helps but not sufficient alone
4. **Redis security**: Ensure Redis is not publicly accessible
5. **Data privacy**: Rate limit keys use IDs, not sensitive data

## References

- [Redis Sorted Sets](https://redis.io/docs/data-types/sorted-sets/)
- [Sliding Window Rate Limiting](https://blog.cloudflare.com/counting-things-a-lot-of-different-things/)
- [HTTP 429 Too Many Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/429)
- [Rate Limit Headers](https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-07.html)
