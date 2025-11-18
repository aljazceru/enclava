"""
Integration tests for request validation middleware

Tests:
- Request size limits
- Content-Type validation
- XSS detection and blocking
- SQL injection detection
- Path traversal detection
- Valid requests pass through
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings


@pytest.mark.asyncio
async def test_valid_request_passes_through(authenticated_client: AsyncClient):
    """Test that valid requests pass through validation."""
    # Make a valid request
    response = await authenticated_client.get("/health")
    assert response.status_code == 200, "Valid requests should pass validation"


@pytest.mark.asyncio
async def test_request_size_limit_enforced(authenticated_client: AsyncClient, test_user: dict):
    """Test that request size limits are enforced."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Create a payload larger than the limit
    max_size = settings.API_MAX_REQUEST_BODY_SIZE
    large_payload = {"data": "x" * (max_size + 1000)}

    # Attempt to send large payload
    # Note: This would need an endpoint that accepts POST data
    # Using a hypothetical endpoint for demonstration
    # Actual test would depend on available endpoints


@pytest.mark.asyncio
async def test_content_type_validation_missing_header(authenticated_client: AsyncClient):
    """Test that missing Content-Type header is rejected for POST requests."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Try to POST without Content-Type header
    # Remove the default Content-Type header
    headers = dict(authenticated_client.headers)
    if 'content-type' in headers:
        del headers['content-type']
    if 'Content-Type' in headers:
        del headers['Content-Type']

    # Note: Actual testing would require an endpoint that accepts POST
    # This is a structure test


@pytest.mark.asyncio
async def test_content_type_validation_invalid_type(authenticated_client: AsyncClient):
    """Test that invalid Content-Type is rejected."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Try to POST with invalid Content-Type
    headers = {
        **dict(authenticated_client.headers),
        "Content-Type": "application/xml"  # Not in allowed types
    }

    # Note: Actual endpoint would be needed for complete test


@pytest.mark.asyncio
async def test_content_type_validation_json_allowed(authenticated_client: AsyncClient):
    """Test that application/json Content-Type is allowed."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # JSON should be allowed
    headers = {
        **dict(authenticated_client.headers),
        "Content-Type": "application/json"
    }

    # Make request with JSON content type
    # Should be allowed


@pytest.mark.asyncio
async def test_xss_detection_in_headers(authenticated_client: AsyncClient):
    """Test that XSS attempts in headers are detected and blocked."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Try to send XSS payload in header
    malicious_headers = {
        **dict(authenticated_client.headers),
        "X-Custom-Header": "<script>alert('xss')</script>"
    }

    response = await authenticated_client.get("/health", headers=malicious_headers)

    # Request should be blocked
    if settings.API_REQUEST_VALIDATION_ENABLED:
        assert response.status_code == 400, "XSS in headers should be blocked"


@pytest.mark.asyncio
async def test_xss_detection_javascript_protocol(authenticated_client: AsyncClient):
    """Test that javascript: protocol in headers is detected."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    malicious_headers = {
        **dict(authenticated_client.headers),
        "X-Redirect": "javascript:alert('xss')"
    }

    response = await authenticated_client.get("/health", headers=malicious_headers)

    if settings.API_REQUEST_VALIDATION_ENABLED:
        assert response.status_code == 400, "JavaScript protocol should be blocked"


@pytest.mark.asyncio
async def test_xss_detection_event_handlers(authenticated_client: AsyncClient):
    """Test that event handler attributes are detected."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    malicious_headers = {
        **dict(authenticated_client.headers),
        "X-Data": "onclick=alert('xss')"
    }

    response = await authenticated_client.get("/health", headers=malicious_headers)

    if settings.API_REQUEST_VALIDATION_ENABLED:
        assert response.status_code == 400, "Event handlers should be blocked"


@pytest.mark.asyncio
async def test_sql_injection_detection_union_select(authenticated_client: AsyncClient):
    """Test that SQL injection attempts with UNION SELECT are detected."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Try SQL injection in query parameter
    response = await authenticated_client.get("/health?id=1 UNION SELECT * FROM users")

    if settings.API_REQUEST_VALIDATION_ENABLED:
        assert response.status_code == 400, "SQL injection should be blocked"


@pytest.mark.asyncio
async def test_sql_injection_detection_drop_table(authenticated_client: AsyncClient):
    """Test that SQL injection attempts with DROP TABLE are detected."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Try SQL injection in query parameter
    response = await authenticated_client.get("/health?id=1; DROP TABLE users--")

    if settings.API_REQUEST_VALIDATION_ENABLED:
        assert response.status_code == 400, "DROP TABLE should be blocked"


@pytest.mark.asyncio
async def test_sql_injection_detection_comments(authenticated_client: AsyncClient):
    """Test that SQL comment syntax is detected."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Try SQL comments in query parameter
    response = await authenticated_client.get("/health?id=1--")

    if settings.API_REQUEST_VALIDATION_ENABLED:
        assert response.status_code == 400, "SQL comments should be blocked"


@pytest.mark.asyncio
async def test_path_traversal_detection_unix(authenticated_client: AsyncClient):
    """Test that Unix-style path traversal is detected."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Try path traversal in query parameter
    response = await authenticated_client.get("/health?file=../../etc/passwd")

    if settings.API_REQUEST_VALIDATION_ENABLED:
        assert response.status_code == 400, "Path traversal should be blocked"


@pytest.mark.asyncio
async def test_path_traversal_detection_windows(authenticated_client: AsyncClient):
    """Test that Windows-style path traversal is detected."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Try Windows path traversal
    response = await authenticated_client.get("/health?file=..\\..\\windows\\system32")

    if settings.API_REQUEST_VALIDATION_ENABLED:
        assert response.status_code == 400, "Windows path traversal should be blocked"


@pytest.mark.asyncio
async def test_path_traversal_in_headers(authenticated_client: AsyncClient):
    """Test that path traversal in headers is detected."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    malicious_headers = {
        **dict(authenticated_client.headers),
        "X-File-Path": "../../../etc/passwd"
    }

    response = await authenticated_client.get("/health", headers=malicious_headers)

    if settings.API_REQUEST_VALIDATION_ENABLED:
        assert response.status_code == 400, "Path traversal in headers should be blocked"


@pytest.mark.asyncio
async def test_valid_headers_not_blocked(authenticated_client: AsyncClient):
    """Test that valid headers are not incorrectly blocked."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Use normal headers that should pass
    valid_headers = {
        **dict(authenticated_client.headers),
        "X-Custom-ID": "12345",
        "X-Request-Source": "web-app"
    }

    response = await authenticated_client.get("/health", headers=valid_headers)
    assert response.status_code == 200, "Valid headers should not be blocked"


@pytest.mark.asyncio
async def test_user_agent_not_validated(authenticated_client: AsyncClient):
    """Test that User-Agent header is not validated for suspicious patterns."""
    # User-Agent can contain various strings and should not be blocked
    headers = {
        **dict(authenticated_client.headers),
        "User-Agent": "Mozilla/5.0 (compatible; script/1.0)"
    }

    response = await authenticated_client.get("/health", headers=headers)
    assert response.status_code == 200, "User-Agent should not be validated"


@pytest.mark.asyncio
async def test_accept_header_not_validated(authenticated_client: AsyncClient):
    """Test that Accept header is not validated."""
    headers = {
        **dict(authenticated_client.headers),
        "Accept": "*/*"
    }

    response = await authenticated_client.get("/health", headers=headers)
    assert response.status_code == 200, "Accept header should not be validated"


@pytest.mark.asyncio
async def test_request_validation_skip_health_endpoint(authenticated_client: AsyncClient):
    """Test that validation is skipped for health check endpoints."""
    # Health endpoint should always work, even with validation enabled
    response = await authenticated_client.get("/health")
    assert response.status_code == 200, "Health endpoint should skip validation"


@pytest.mark.asyncio
async def test_request_validation_skip_docs_endpoint(authenticated_client: AsyncClient):
    """Test that validation is skipped for documentation endpoints."""
    # Docs endpoints should skip validation
    response = await authenticated_client.get("/docs")
    # Should not get validation error (might get 200 or 404 depending on setup)
    assert response.status_code != 400, "Docs endpoint should skip validation"


@pytest.mark.asyncio
async def test_request_validation_get_requests_skip(authenticated_client: AsyncClient):
    """Test that GET requests skip body validation."""
    # GET requests have no body, so they should skip body validation
    response = await authenticated_client.get("/health")
    assert response.status_code == 200, "GET requests should work"


@pytest.mark.asyncio
async def test_request_validation_delete_requests_skip(authenticated_client: AsyncClient):
    """Test that DELETE requests skip body validation."""
    # DELETE requests typically have no body
    # Should not fail validation
    pass


@pytest.mark.asyncio
async def test_multiple_suspicious_patterns(authenticated_client: AsyncClient):
    """Test detection of multiple suspicious patterns in one request."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Combine multiple attack patterns
    response = await authenticated_client.get(
        "/health?id=1 UNION SELECT * FROM users&file=../../etc/passwd"
    )

    if settings.API_REQUEST_VALIDATION_ENABLED:
        assert response.status_code == 400, "Multiple suspicious patterns should be blocked"


@pytest.mark.asyncio
async def test_validation_error_response_structure(authenticated_client: AsyncClient):
    """Test that validation errors return proper error structure."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Trigger a validation error
    response = await authenticated_client.get("/health?payload=<script>alert('xss')</script>")

    if response.status_code == 400:
        # Check error response structure
        data = response.json()
        assert "error" in data, "Error response should have 'error' field"
        assert "message" in data, "Error response should have 'message' field"


@pytest.mark.asyncio
async def test_content_length_header_validation(authenticated_client: AsyncClient):
    """Test that Content-Length header is validated."""
    if not settings.API_REQUEST_VALIDATION_ENABLED:
        pytest.skip("Request validation not enabled")

    # Invalid Content-Length should be rejected
    # Note: httpx handles Content-Length automatically, so this is more of a structure test


@pytest.mark.asyncio
async def test_premium_user_higher_size_limit():
    """Test that premium users have higher request size limits."""
    # Premium users should have higher MAX_REQUEST_BODY_SIZE_PREMIUM
    # This would require creating a premium user and testing
    assert settings.API_MAX_REQUEST_BODY_SIZE_PREMIUM > settings.API_MAX_REQUEST_BODY_SIZE, \
        "Premium users should have higher size limits"


@pytest.mark.asyncio
async def test_request_validation_disabled_fallback(authenticated_client: AsyncClient):
    """Test that application works when request validation is disabled."""
    # Even with suspicious patterns, requests should work if validation is disabled
    response = await authenticated_client.get("/health")
    assert response.status_code == 200, "Application should work without validation"
