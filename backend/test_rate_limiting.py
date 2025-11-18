#!/usr/bin/env python3
"""
Simple validation script for rate limiting middleware
This verifies imports and basic configuration
"""

import sys
import os

# Add backend directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

def test_imports():
    """Test that all necessary imports work"""
    print("Testing imports...")

    try:
        from app.middleware.rate_limiting import (
            RateLimiter,
            RateLimitMiddleware,
            RateLimitExceeded,
            setup_rate_limiting_middleware
        )
        print("✓ Rate limiting middleware imports successful")
        return True
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False

def test_config():
    """Test that configuration is properly set up"""
    print("\nTesting configuration...")

    try:
        from app.core.config import settings

        # Check that all required config variables exist
        config_vars = [
            'API_RATE_LIMITING_ENABLED',
            'API_RATE_LIMIT_ANONYMOUS_PER_MINUTE',
            'API_RATE_LIMIT_ANONYMOUS_PER_HOUR',
            'API_RATE_LIMIT_AUTHENTICATED_PER_MINUTE',
            'API_RATE_LIMIT_AUTHENTICATED_PER_HOUR',
            'API_RATE_LIMIT_API_KEY_PER_MINUTE',
            'API_RATE_LIMIT_API_KEY_PER_HOUR',
            'API_RATE_LIMIT_PREMIUM_PER_MINUTE',
            'API_RATE_LIMIT_PREMIUM_PER_HOUR',
            'API_RATE_LIMIT_WHITELIST_IPS',
        ]

        missing = []
        for var in config_vars:
            if not hasattr(settings, var):
                missing.append(var)

        if missing:
            print(f"✗ Missing config variables: {', '.join(missing)}")
            return False

        print("✓ All configuration variables present")

        # Print current configuration
        print("\nCurrent Rate Limit Configuration:")
        print(f"  Enabled: {settings.API_RATE_LIMITING_ENABLED}")
        print(f"  Whitelist IPs: {settings.API_RATE_LIMIT_WHITELIST_IPS}")
        print(f"  Anonymous: {settings.API_RATE_LIMIT_ANONYMOUS_PER_MINUTE}/min, {settings.API_RATE_LIMIT_ANONYMOUS_PER_HOUR}/hr")
        print(f"  Authenticated: {settings.API_RATE_LIMIT_AUTHENTICATED_PER_MINUTE}/min, {settings.API_RATE_LIMIT_AUTHENTICATED_PER_HOUR}/hr")
        print(f"  API Key: {settings.API_RATE_LIMIT_API_KEY_PER_MINUTE}/min, {settings.API_RATE_LIMIT_API_KEY_PER_HOUR}/hr")
        print(f"  Premium: {settings.API_RATE_LIMIT_PREMIUM_PER_MINUTE}/min, {settings.API_RATE_LIMIT_PREMIUM_PER_HOUR}/hr")

        return True

    except Exception as e:
        print(f"✗ Configuration error: {e}")
        return False

def test_middleware_structure():
    """Test that middleware has proper structure"""
    print("\nTesting middleware structure...")

    try:
        from app.middleware.rate_limiting import RateLimitMiddleware
        import inspect

        # Check that RateLimitMiddleware has dispatch method
        if not hasattr(RateLimitMiddleware, 'dispatch'):
            print("✗ RateLimitMiddleware missing dispatch method")
            return False

        # Check that it's async
        if not inspect.iscoroutinefunction(RateLimitMiddleware.dispatch):
            print("✗ dispatch method is not async")
            return False

        print("✓ Middleware structure is correct")
        return True

    except Exception as e:
        print(f"✗ Middleware structure error: {e}")
        return False

def test_api_key_model():
    """Test that API key model has rate limit fields"""
    print("\nTesting API key model...")

    try:
        from app.models.api_key import APIKey

        # Check that APIKey has rate limit fields
        required_fields = [
            'rate_limit_per_minute',
            'rate_limit_per_hour',
            'rate_limit_per_day'
        ]

        sample_key = APIKey.__table__.columns
        column_names = [col.name for col in sample_key]

        missing = [field for field in required_fields if field not in column_names]

        if missing:
            print(f"✗ Missing API key fields: {', '.join(missing)}")
            return False

        print("✓ API key model has required fields")
        return True

    except Exception as e:
        print(f"✗ API key model error: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("Rate Limiting Middleware Validation")
    print("=" * 60)

    tests = [
        ("Imports", test_imports),
        ("Configuration", test_config),
        ("Middleware Structure", test_middleware_structure),
        ("API Key Model", test_api_key_model),
    ]

    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"\n✗ {test_name} failed with exception: {e}")
            results[test_name] = False

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)

    passed = sum(1 for result in results.values() if result)
    total = len(results)

    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n✓ All validation tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
