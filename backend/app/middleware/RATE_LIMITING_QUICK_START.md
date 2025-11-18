# Rate Limiting Quick Start Guide

## TL;DR

Rate limiting is **enabled by default** and works automatically for all API endpoints.

## How It Works

- **Anonymous users**: 10 req/min, 100 req/hour (IP-based)
- **Authenticated users**: 20 req/min, 1,200 req/hour (user-based)
- **API key users**: 20 req/min, 1,200 req/hour (customizable per key)
- **Premium users**: 20 req/min, 1,200 req/hour (role-based)

## Quick Configuration

### Disable Rate Limiting

Add to `.env`:
```bash
API_RATE_LIMITING_ENABLED=false
```

### Whitelist an IP

Add to `.env`:
```bash
API_RATE_LIMIT_WHITELIST_IPS=127.0.0.1,::1,10.0.0.5,192.168.1.100
```

### Adjust Limits

Add to `.env`:
```bash
# Anonymous users
API_RATE_LIMIT_ANONYMOUS_PER_MINUTE=20
API_RATE_LIMIT_ANONYMOUS_PER_HOUR=200

# Authenticated users
API_RATE_LIMIT_AUTHENTICATED_PER_MINUTE=60
API_RATE_LIMIT_AUTHENTICATED_PER_HOUR=3600

# API key users
API_RATE_LIMIT_API_KEY_PER_MINUTE=100
API_RATE_LIMIT_API_KEY_PER_HOUR=6000

# Premium users
API_RATE_LIMIT_PREMIUM_PER_MINUTE=200
API_RATE_LIMIT_PREMIUM_PER_HOUR=12000
```

### Custom Limits for Specific API Key

Using Python:
```python
from app.models.api_key import APIKey

# Create API key with custom limits
api_key = APIKey(
    name="High Volume Integration",
    rate_limit_per_minute=1000,  # Custom: 1000/min
    rate_limit_per_hour=60000,   # Custom: 60000/hour
    # ... other fields
)
db.add(api_key)
db.commit()
```

Using API:
```bash
curl -X POST http://localhost:8000/api/v1/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "High Volume Integration",
    "rate_limit_per_minute": 1000,
    "rate_limit_per_hour": 60000
  }'
```

## Response Headers

Every response includes rate limit information:

```http
X-RateLimit-Limit-Minute: 20
X-RateLimit-Remaining-Minute: 15
X-RateLimit-Reset-Minute: 1700000060

X-RateLimit-Limit-Hour: 1200
X-RateLimit-Remaining-Hour: 1185
X-RateLimit-Reset-Hour: 1700003600
```

## Rate Limit Exceeded Response

When you exceed the rate limit, you get:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 30
X-RateLimit-Limit-Minute: 20
X-RateLimit-Remaining-Minute: 0
X-RateLimit-Reset-Minute: 1700000060

{
  "error": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded. Please try again later.",
  "details": {
    "limit_per_minute": 20,
    "limit_per_hour": 1200,
    "retry_after": 30
  }
}
```

## Testing Rate Limits

### Check Current Limits

```bash
# Make a request and check headers
curl -v http://localhost:8000/api/v1/some-endpoint 2>&1 | grep "X-RateLimit"
```

### Test Exceeding Limits

```bash
# Run 15 requests quickly
for i in {1..15}; do
  echo "Request $i:"
  curl http://localhost:8000/api/v1/some-endpoint
  echo ""
done
```

### Test with Different Auth Types

```bash
# Anonymous (IP-based, 10/min)
curl http://localhost:8000/api/v1/some-endpoint

# With API key (20/min default, or custom)
curl -H "X-API-Key: en_your_api_key" http://localhost:8000/api/v1/some-endpoint

# With JWT (20/min for regular, more for premium)
curl -H "Authorization: Bearer your_jwt_token" http://localhost:8000/api/v1/some-endpoint
```

## Common Issues

### "All my requests are getting rate limited"

**Possible causes**:
1. IP is being shared (NAT/proxy)
2. Rate limits are too low for your use case
3. Multiple services using same IP

**Solutions**:
- Use API key authentication instead of anonymous
- Increase rate limits in `.env`
- Whitelist your IP
- Use different API keys for different services

### "Rate limiting not working"

**Check**:
1. Is `API_RATE_LIMITING_ENABLED=true` in `.env`?
2. Is Redis running? (`docker ps | grep redis`)
3. Is your IP whitelisted by mistake?
4. Check logs: `docker logs enclava-backend | grep rate`

### "Getting 429 errors in tests"

**Solutions**:
1. Whitelist test IP: `API_RATE_LIMIT_WHITELIST_IPS=127.0.0.1,::1`
2. Disable in test env: `API_RATE_LIMITING_ENABLED=false`
3. Add delays between test requests
4. Use different API keys for each test

## Monitoring

### Check Redis for rate limit data

```bash
# Connect to Redis
docker exec -it enclava-redis redis-cli

# List all rate limit keys
KEYS api_rate_limit:*

# Check specific user's rate limit
ZCARD api_rate_limit:minute:user:123
ZCARD api_rate_limit:hour:user:123

# View all requests in minute window
ZRANGE api_rate_limit:minute:user:123 0 -1 WITHSCORES
```

### View logs

```bash
# Backend logs
docker logs -f enclava-backend | grep -i rate

# Filter for rate limit exceeded events
docker logs enclava-backend | grep "Rate limit exceeded"

# Filter for configuration
docker logs enclava-backend | grep "Rate limiting middleware"
```

## Best Practices

### For API Consumers

1. **Monitor headers**: Always check `X-RateLimit-Remaining-*` headers
2. **Implement backoff**: If `X-RateLimit-Remaining-Minute < 5`, slow down
3. **Handle 429**: Respect `Retry-After` header
4. **Use API keys**: Get higher limits than anonymous
5. **Request increase**: Contact admin for higher limits if needed

### For API Providers

1. **Set appropriate limits**: Balance protection vs usability
2. **Monitor usage**: Track who's hitting limits frequently
3. **Custom limits**: Offer higher limits to power users
4. **Document limits**: Make limits clear in API docs
5. **Whitelist carefully**: Only whitelist trusted IPs

## API Client Example

### Python with Retry Logic

```python
import requests
import time

def api_request_with_retry(url, max_retries=3):
    """Make API request with automatic retry on rate limit"""
    for attempt in range(max_retries):
        response = requests.get(url)

        # Check rate limit headers
        remaining = int(response.headers.get('X-RateLimit-Remaining-Minute', 999))

        if response.status_code == 200:
            # Warn if getting close to limit
            if remaining < 5:
                print(f"Warning: Only {remaining} requests remaining this minute")
            return response

        elif response.status_code == 429:
            # Rate limited - respect retry-after
            retry_after = int(response.headers.get('Retry-After', 60))
            print(f"Rate limited. Retrying after {retry_after} seconds...")
            time.sleep(retry_after)
            continue

        else:
            # Other error
            response.raise_for_status()

    raise Exception("Max retries exceeded")

# Usage
response = api_request_with_retry('http://localhost:8000/api/v1/endpoint')
print(response.json())
```

### JavaScript/Node.js with Retry Logic

```javascript
const axios = require('axios');

async function apiRequestWithRetry(url, maxRetries = 3) {
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await axios.get(url);

      // Check rate limit headers
      const remaining = parseInt(response.headers['x-ratelimit-remaining-minute'] || 999);

      if (remaining < 5) {
        console.warn(`Warning: Only ${remaining} requests remaining this minute`);
      }

      return response.data;

    } catch (error) {
      if (error.response && error.response.status === 429) {
        // Rate limited - respect retry-after
        const retryAfter = parseInt(error.response.headers['retry-after'] || 60);
        console.log(`Rate limited. Retrying after ${retryAfter} seconds...`);
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        continue;
      }
      throw error;
    }
  }
  throw new Error('Max retries exceeded');
}

// Usage
apiRequestWithRetry('http://localhost:8000/api/v1/endpoint')
  .then(data => console.log(data))
  .catch(err => console.error(err));
```

## FAQ

**Q: Can I have different limits for different endpoints?**
A: Not currently. This is a planned future enhancement.

**Q: What happens if Redis goes down?**
A: Requests are allowed but logged. API stays up.

**Q: Can I bypass rate limiting for admin users?**
A: Yes, super_admin role gets premium tier limits. Or whitelist their IP.

**Q: How do I increase limits for a customer?**
A: Create a custom API key with higher limits, or upgrade their user role to premium.

**Q: Does rate limiting work across multiple backend instances?**
A: Yes, it uses shared Redis so works across all instances.

**Q: What's the overhead of rate limiting?**
A: Approximately 2-5ms per request (Redis pipeline latency).

## Support

For issues or questions:
1. Check logs: `docker logs enclava-backend | grep rate`
2. Check Redis: `docker exec -it enclava-redis redis-cli ping`
3. Review docs: `backend/app/middleware/RATE_LIMITING.md`
4. Contact: [your-support-email]
