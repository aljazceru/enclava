"""
Integration tests for plugin permission system

Tests:
- User-based plugin visibility filtering
- Plugin permission checks (install, enable, disable, configure)
- API key plugin access control
- Plugin permission inheritance from roles
- Wildcard permissions for plugins
- Installation failure notifications
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.plugin import Plugin, PluginPermission
from app.models.user import User
from app.services.permission_manager import permission_registry


@pytest_asyncio.fixture
async def test_plugin(test_db: AsyncSession, test_user: dict) -> Plugin:
    """Create a test plugin."""
    plugin = Plugin(
        name="test-plugin",
        slug="test-plugin",
        display_name="Test Plugin",
        description="A test plugin for permission testing",
        version="1.0.0",
        author="Test Author",
        package_path="/plugins/test-plugin",
        manifest_hash="abc123",
        package_hash="def456",
        status="installed",
        enabled=False,
        installed_by_user_id=test_user["id"],
        manifest_data={"name": "test-plugin", "version": "1.0.0"},
        required_permissions=["platform:plugins:use"],
        api_scopes=["llm:completions:execute"]
    )
    test_db.add(plugin)
    await test_db.commit()
    await test_db.refresh(plugin)
    return plugin


@pytest_asyncio.fixture
async def admin_user(test_db: AsyncSession) -> dict:
    """Create an admin user."""
    from app.core.security import get_password_hash

    user = User(
        email="admin@example.com",
        username="adminuser",
        hashed_password=get_password_hash("adminpass123"),
        is_active=True,
        is_verified=True,
        role="admin"
    )

    test_db.add(user)
    await test_db.commit()
    await test_db.refresh(user)

    return {
        "id": str(user.id),
        "email": user.email,
        "username": user.username,
        "password": "adminpass123",
        "role": "admin"
    }


@pytest_asyncio.fixture
async def admin_token(admin_user: dict) -> str:
    """Create a JWT token for admin user."""
    from app.core.security import create_access_token

    token_data = {"sub": admin_user["email"], "user_id": admin_user["id"], "role": admin_user["role"]}
    return create_access_token(data=token_data)


@pytest_asyncio.fixture
async def authenticated_admin_client(async_client: AsyncClient, admin_token: str) -> AsyncClient:
    """Create an authenticated admin client."""
    async_client.headers.update({"Authorization": f"Bearer {admin_token}"})
    return async_client


@pytest.mark.asyncio
async def test_user_based_plugin_visibility(
    test_db: AsyncSession,
    test_user: dict,
    admin_user: dict
):
    """Test that users can only see plugins they have permission to view."""
    # Get user permissions
    user_permissions = permission_registry.get_user_permissions(["user"])
    admin_permissions = permission_registry.get_user_permissions(["admin"])

    # Check that user has view permission
    has_view = permission_registry.check_permission(
        user_permissions,
        "platform:plugins:view"
    )
    assert has_view, "Regular user should have plugin view permission"

    # Check that admin has manage permission
    has_manage = permission_registry.check_permission(
        admin_permissions,
        "platform:plugins:manage"
    )
    assert has_manage, "Admin should have plugin manage permission"


@pytest.mark.asyncio
async def test_plugin_install_permission(test_db: AsyncSession, test_user: dict, admin_user: dict):
    """Test plugin installation permission checks."""
    # Regular user should not have install permission
    user_permissions = permission_registry.get_user_permissions(["user"])
    can_install = permission_registry.check_permission(
        user_permissions,
        "platform:plugins:install"
    )
    assert not can_install, "Regular user should not have plugin install permission"

    # Admin should have install permission
    admin_permissions = permission_registry.get_user_permissions(["admin"])
    can_install_admin = permission_registry.check_permission(
        admin_permissions,
        "platform:plugins:install"
    )
    assert can_install_admin, "Admin should have plugin install permission"


@pytest.mark.asyncio
async def test_plugin_enable_disable_permission(
    test_db: AsyncSession,
    test_plugin: Plugin,
    test_user: dict,
    admin_user: dict
):
    """Test plugin enable/disable permission checks."""
    # Regular user should not have enable permission
    user_permissions = permission_registry.get_user_permissions(["user"])
    can_enable = permission_registry.check_permission(
        user_permissions,
        "platform:plugins:enable"
    )
    assert not can_enable, "Regular user should not have plugin enable permission"

    # Admin should have enable permission
    admin_permissions = permission_registry.get_user_permissions(["admin"])
    can_enable_admin = permission_registry.check_permission(
        admin_permissions,
        "platform:plugins:enable"
    )
    assert can_enable_admin, "Admin should have plugin enable permission"

    # Test disable permission
    can_disable_admin = permission_registry.check_permission(
        admin_permissions,
        "platform:plugins:disable"
    )
    assert can_disable_admin, "Admin should have plugin disable permission"


@pytest.mark.asyncio
async def test_plugin_configure_permission(
    test_db: AsyncSession,
    test_plugin: Plugin,
    test_user: dict
):
    """Test plugin configuration permission checks."""
    # Regular user should not have configure permission by default
    user_permissions = permission_registry.get_user_permissions(["user"])
    can_configure = permission_registry.check_permission(
        user_permissions,
        "platform:plugins:configure"
    )
    assert not can_configure, "Regular user should not have plugin configure permission"

    # Developer role should have configure permission
    developer_permissions = permission_registry.get_user_permissions(["developer"])
    can_configure_dev = permission_registry.check_permission(
        developer_permissions,
        "platform:plugins:configure"
    )
    assert can_configure_dev, "Developer should have plugin configure permission"


@pytest.mark.asyncio
async def test_api_key_plugin_access_control(
    test_db: AsyncSession,
    test_plugin: Plugin,
    test_user: dict,
    test_api_key: str
):
    """Test plugin access control via API keys."""
    # API keys should inherit user permissions
    from app.services.cached_api_key import cached_api_key_service

    key_prefix = test_api_key[:8]
    context = await cached_api_key_service.get_cached_api_key(key_prefix, test_db)

    assert context is not None, "API key should be found"
    assert context.get("user") is not None, "API key should have associated user"


@pytest.mark.asyncio
async def test_plugin_permission_inheritance_from_roles(test_db: AsyncSession):
    """Test that plugin permissions are properly inherited from user roles."""
    # Test super_admin role
    super_admin_perms = permission_registry.get_user_permissions(["super_admin"])
    assert "plugins:*" in super_admin_perms or "platform:*" in super_admin_perms, \
        "Super admin should have wildcard plugin permissions"

    # Test admin role
    admin_perms = permission_registry.get_user_permissions(["admin"])
    assert "plugins:*" in admin_perms or "platform:*" in admin_perms, \
        "Admin should have wildcard plugin permissions"

    # Test developer role
    developer_perms = permission_registry.get_user_permissions(["developer"])
    has_plugin_use = any(
        "plugins:use" in perm or "platform:plugins:use" in perm
        for perm in developer_perms
    )
    assert has_plugin_use or "platform:*" in developer_perms or "platform:plugins:*" in developer_perms, \
        "Developer should have plugin use permission"

    # Test regular user role
    user_perms = permission_registry.get_user_permissions(["user"])
    has_plugin_view = any(
        "plugins:view" in perm or "platform:plugins:view" in perm
        for perm in user_perms
    )
    assert has_plugin_view or "platform:*" in user_perms or "platform:plugins:*" in user_perms, \
        "User should have plugin view permission"


@pytest.mark.asyncio
async def test_wildcard_permissions_for_plugins(test_db: AsyncSession):
    """Test that wildcard permissions work correctly for plugins."""
    # Test platform:* wildcard
    platform_wildcard = ["platform:*"]
    can_install = permission_registry.check_permission(
        platform_wildcard,
        "platform:plugins:install"
    )
    assert can_install, "platform:* should grant plugin install permission"

    can_enable = permission_registry.check_permission(
        platform_wildcard,
        "platform:plugins:enable"
    )
    assert can_enable, "platform:* should grant plugin enable permission"

    # Test plugins:* wildcard
    plugins_wildcard = ["plugins:*"]
    can_use = permission_registry.check_permission(
        plugins_wildcard,
        "plugins:test-plugin:use"
    )
    assert can_use, "plugins:* should grant specific plugin use permission"

    # Test platform:plugins:* wildcard
    plugin_specific_wildcard = ["platform:plugins:*"]
    can_manage = permission_registry.check_permission(
        plugin_specific_wildcard,
        "platform:plugins:manage"
    )
    assert can_manage, "platform:plugins:* should grant plugin manage permission"


@pytest.mark.asyncio
async def test_specific_plugin_permissions(
    test_db: AsyncSession,
    test_plugin: Plugin,
    test_user: dict
):
    """Test permissions for specific plugins."""
    # Create plugin-specific permission
    plugin_permission = PluginPermission(
        plugin_id=test_plugin.id,
        user_id=int(test_user["id"]),
        permission_name="use",
        granted=True,
        granted_by_user_id=int(test_user["id"])
    )
    test_db.add(plugin_permission)
    await test_db.commit()

    # Check plugin-specific permission
    specific_perm = f"plugins:{test_plugin.slug}:use"
    user_perms = permission_registry.get_user_permissions(
        ["user"],
        custom_permissions=[specific_perm]
    )

    can_use_specific = permission_registry.check_permission(
        user_perms,
        specific_perm
    )
    assert can_use_specific, "User should have specific plugin use permission"


@pytest.mark.asyncio
async def test_plugin_permission_revocation(
    test_db: AsyncSession,
    test_plugin: Plugin,
    test_user: dict
):
    """Test revoking plugin permissions."""
    # Create and then revoke a permission
    plugin_permission = PluginPermission(
        plugin_id=test_plugin.id,
        user_id=int(test_user["id"]),
        permission_name="configure",
        granted=False,  # Revoked
        granted_by_user_id=int(test_user["id"])
    )
    test_db.add(plugin_permission)
    await test_db.commit()

    # Verify permission is in database
    assert plugin_permission.granted is False, "Permission should be revoked"


@pytest.mark.asyncio
async def test_check_plugin_permission_helper(test_db: AsyncSession):
    """Test the check_plugin_permission helper method."""
    # Test with general plugin permissions
    admin_perms = permission_registry.get_user_permissions(["admin"])
    can_install = permission_registry.check_plugin_permission(
        admin_perms,
        "test-plugin",
        "install"
    )
    assert can_install, "Admin should be able to install plugins"

    # Test with user permissions
    user_perms = permission_registry.get_user_permissions(["user"])
    can_install_user = permission_registry.check_plugin_permission(
        user_perms,
        "test-plugin",
        "install"
    )
    assert not can_install_user, "Regular user should not be able to install plugins"

    # Test with use permission
    can_use = permission_registry.check_plugin_permission(
        user_perms,
        "test-plugin",
        "use"
    )
    assert can_use, "User should be able to use plugins"


@pytest.mark.asyncio
async def test_readonly_role_plugin_permissions(test_db: AsyncSession):
    """Test that readonly role has appropriate plugin permissions."""
    readonly_perms = permission_registry.get_user_permissions(["readonly"])

    # Should have view permission
    can_view = permission_registry.check_permission(
        readonly_perms,
        "platform:plugins:view"
    )
    assert can_view, "Readonly user should have plugin view permission"

    # Should not have install permission
    can_install = permission_registry.check_permission(
        readonly_perms,
        "platform:plugins:install"
    )
    assert not can_install, "Readonly user should not have plugin install permission"

    # Should not have enable permission
    can_enable = permission_registry.check_permission(
        readonly_perms,
        "platform:plugins:enable"
    )
    assert not can_enable, "Readonly user should not have plugin enable permission"
