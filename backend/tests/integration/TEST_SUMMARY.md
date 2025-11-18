# Integration Tests Summary

## Overview
Comprehensive integration tests have been created for new features in the Enclava backend platform.

## Test Files Created

### 1. test_plugin_permissions.py (386 lines)
**Location:** `/home/user/enclava/backend/tests/integration/test_plugin_permissions.py`

**Coverage:**
- ✅ User-based plugin visibility filtering
- ✅ Plugin permission checks (install, enable, disable, configure)
- ✅ API key plugin access control
- ✅ Plugin permission inheritance from roles (super_admin, admin, developer, user, readonly)
- ✅ Wildcard permissions for plugins (platform:*, plugins:*, platform:plugins:*)
- ✅ Specific plugin permissions
- ✅ Plugin permission revocation
- ✅ check_plugin_permission helper method testing

**Test Count:** 13 tests

**Key Features Tested:**
- Permission hierarchy and inheritance
- Role-based access control
- Wildcard pattern matching
- Plugin-specific permissions
- Permission validation for different user roles

---

### 2. test_security_middleware.py (288 lines)
**Location:** `/home/user/enclava/backend/tests/integration/test_security_middleware.py`

**Coverage:**
- ✅ Request ID generation and tracking
- ✅ Security headers (CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection)
- ✅ Request ID preservation from client
- ✅ HSTS header for HTTPS
- ✅ Permissions-Policy restrictions
- ✅ Security headers on error responses
- ✅ Request ID uniqueness
- ✅ Middleware graceful degradation

**Test Count:** 18 tests

**Key Features Tested:**
- RequestIDMiddleware functionality
- SecurityHeadersMiddleware configuration
- IPFilterMiddleware (structure tests)
- ErrorSanitizationMiddleware
- Security header consistency across endpoints

---

### 3. test_rate_limiting.py (330 lines)
**Location:** `/home/user/enclava/backend/tests/integration/test_rate_limiting.py`

**Coverage:**
- ✅ Anonymous user rate limits
- ✅ Authenticated user rate limits
- ✅ API key rate limits
- ✅ Custom per-API-key rate limits
- ✅ Rate limit headers in responses (X-RateLimit-Limit-Minute, X-RateLimit-Remaining-Minute, etc.)
- ✅ 429 responses when limit exceeded
- ✅ IP whitelist bypassing rate limits
- ✅ Rate limiting across multiple requests
- ✅ Separate rate limit counters per user
- ✅ Per-minute and per-hour windows

**Test Count:** 16 tests

**Key Features Tested:**
- Sliding window rate limiting algorithm
- Multi-tier rate limits (anonymous, authenticated, API key, premium)
- Rate limit header presence and accuracy
- Whitelist functionality
- Redis integration for rate tracking
- Graceful degradation when Redis unavailable

---

### 4. test_request_validation.py (359 lines)
**Location:** `/home/user/enclava/backend/tests/integration/test_request_validation.py`

**Coverage:**
- ✅ Request size limits (standard and premium)
- ✅ Content-Type validation
- ✅ XSS detection and blocking
  - Script tags
  - JavaScript protocol
  - Event handlers
- ✅ SQL injection detection
  - UNION SELECT
  - DROP TABLE
  - SQL comments
- ✅ Path traversal detection
  - Unix-style (../)
  - Windows-style (..\)
- ✅ Valid requests pass through
- ✅ Header validation with exceptions (User-Agent, Accept)
- ✅ Validation skip for specific endpoints (health, docs)

**Test Count:** 22 tests

**Key Features Tested:**
- Request body size enforcement
- Content-Type validation for POST/PUT/PATCH
- XSS attack pattern detection
- SQL injection pattern detection
- Path traversal attack prevention
- Proper error response structure
- Middleware skip logic

---

### 5. test_chatbot_rag_integration.py (497 lines)
**Location:** `/home/user/enclava/backend/tests/integration/test_chatbot_rag_integration.py`

**Coverage:**
- ✅ Chatbot creation with RAG collection
- ✅ Chatbot creation without RAG
- ✅ Chatbot chat with RAG context injection
- ✅ RAG document retrieval in chatbot
- ✅ Chatbot without RAG collection
- ✅ Chatbot RAG with empty collection
- ✅ Conversation management
- ✅ Message storage with RAG sources
- ✅ Conversation history retrieval
- ✅ Multiple conversations per chatbot
- ✅ Cascade delete behavior
- ✅ Analytics tracking with RAG usage

**Test Count:** 18 tests

**Key Features Tested:**
- ChatbotInstance model with RAG configuration
- ChatbotConversation management
- ChatbotMessage storage with source tracking
- RAG collection integration
- Qdrant vector database interaction
- Analytics event tracking
- Cascade delete relationships

---

## Total Statistics

- **Total Test Files:** 5
- **Total Lines of Code:** 1,860
- **Total Test Cases:** 87+
- **Framework:** pytest with pytest-asyncio
- **Fixtures Used:**
  - test_db (database session)
  - async_client (HTTP client)
  - authenticated_client (authenticated HTTP client)
  - api_key_client (API key authenticated client)
  - test_user (test user fixture)
  - admin_user (admin user fixture)
  - test_plugin (plugin fixture)
  - test_chatbot (chatbot fixture)
  - test_qdrant_collection (Qdrant collection fixture)

---

## Running the Tests

### Run all integration tests:
```bash
cd /home/user/enclava/backend
pytest tests/integration/
```

### Run specific test file:
```bash
pytest tests/integration/test_plugin_permissions.py
pytest tests/integration/test_security_middleware.py
pytest tests/integration/test_rate_limiting.py
pytest tests/integration/test_request_validation.py
pytest tests/integration/test_chatbot_rag_integration.py
```

### Run with verbose output:
```bash
pytest tests/integration/test_plugin_permissions.py -v
```

### Run with coverage:
```bash
pytest tests/integration/ --cov=app --cov-report=html
```

---

## Dependencies

The tests require the following to be installed (from `requirements-test.txt`):
- pytest
- pytest-asyncio
- httpx
- sqlalchemy
- qdrant-client
- aiohttp
- redis

And the following services to be running:
- PostgreSQL (for database tests)
- Redis (for rate limiting and caching tests)
- Qdrant (for RAG integration tests)

---

## Test Patterns Used

### 1. Async Testing
All tests are async and use `@pytest.mark.asyncio` decorator:
```python
@pytest.mark.asyncio
async def test_example(test_db: AsyncSession):
    # Test implementation
```

### 2. Fixtures
Tests use pytest fixtures for setup and teardown:
```python
@pytest_asyncio.fixture
async def test_plugin(test_db: AsyncSession, test_user: dict) -> Plugin:
    # Create test data
    yield plugin
    # Cleanup handled by fixture scope
```

### 3. Success and Failure Cases
Each feature is tested for both success and failure scenarios:
```python
# Success case
async def test_valid_permission_granted():
    assert has_permission == True

# Failure case
async def test_invalid_permission_denied():
    assert has_permission == False
```

### 4. Edge Cases
Tests include edge cases like:
- Empty collections
- Missing headers
- Disabled features
- Null/None values
- Boundary conditions

---

## Known Issues and Notes

### 1. Environment-Dependent Tests
Some tests depend on configuration settings:
- `API_RATE_LIMITING_ENABLED` must be True for rate limiting tests
- `API_SECURITY_ENABLED` must be True for security middleware tests
- `API_REQUEST_VALIDATION_ENABLED` must be True for validation tests
- Redis must be running and accessible for rate limiting tests
- Qdrant must be running for RAG integration tests

### 2. Skip Conditions
Tests automatically skip when required services are unavailable:
```python
if not settings.API_RATE_LIMITING_ENABLED or not core_cache.enabled:
    pytest.skip("Rate limiting or Redis not enabled")
```

### 3. Whitelist Defaults
Some tests assume localhost (127.0.0.1) is whitelisted by default for rate limiting.

### 4. Test Isolation
- Each test uses its own database session with rollback
- Qdrant collections are created with unique names and cleaned up
- Redis keys use test-specific prefixes

---

## Future Enhancements

### Recommended Additions:
1. **Performance Tests**: Add timing assertions for critical paths
2. **Load Tests**: Test behavior under concurrent requests
3. **Integration with CI/CD**: Add GitHub Actions workflow
4. **Test Data Factories**: Use factory_boy for more flexible test data creation
5. **Mock External Services**: Add mocks for external API calls
6. **End-to-End Tests**: Full workflow tests from user registration to RAG queries

### Coverage Improvements:
1. Add tests for error paths in middleware
2. Test middleware interaction and ordering
3. Add tests for plugin installation failure notifications
4. Test concurrent chatbot conversations
5. Test RAG performance with large document collections

---

## Contributing

When adding new tests:
1. Follow the existing async test pattern
2. Use descriptive test names starting with `test_`
3. Add docstrings explaining what each test does
4. Include both positive and negative test cases
5. Use appropriate fixtures for setup
6. Ensure tests are independent and can run in any order
7. Add skip conditions for environment-dependent tests

---

## Contact

For questions or issues with tests, please refer to:
- Main documentation: `/home/user/enclava/README.md`
- API documentation: `/home/user/enclava/backend/docs/`
- Test configuration: `/home/user/enclava/backend/tests/conftest.py`
