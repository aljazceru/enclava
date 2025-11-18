# Plugin Authorization Implementation Summary

## Overview
Implemented comprehensive frontend authorization logic for plugins in `/home/user/enclava/frontend/src/contexts/PluginContext.tsx`.

## What Was Implemented

### 1. Permission Checking System

#### Core Permission Functions
- **`hasPermission(requiredPermission: string)`**: Checks if the current user has a specific permission
  - Supports exact permission matching (e.g., "plugins:install")
  - Supports wildcard permissions (e.g., "plugins:*" grants all plugin permissions)
  - Automatically grants all permissions to admin and super_admin roles

- **`checkPluginPermission(action: string)`**: Specialized function for checking plugin-specific permissions
  - Actions: install, uninstall, enable, disable, configure, load, unload, view
  - Automatically prefixes with "plugins:" namespace

### 2. Authorization on Plugin Actions

All plugin action functions now include permission checks that:
- Validate user permissions before executing the action
- Return false and set an error message if permission is denied
- Display clear, informative error messages indicating the required permission

#### Protected Actions:
1. **Install Plugin** (`installPlugin`)
   - Required permission: `plugins:install`
   - Error: "You do not have permission to install plugins. Required permission: plugins:install"

2. **Uninstall Plugin** (`uninstallPlugin`)
   - Required permission: `plugins:uninstall`
   - Error: "You do not have permission to uninstall plugins. Required permission: plugins:uninstall"

3. **Enable Plugin** (`enablePlugin`)
   - Required permission: `plugins:enable`
   - Error: "You do not have permission to enable plugins. Required permission: plugins:enable"

4. **Disable Plugin** (`disablePlugin`)
   - Required permission: `plugins:disable`
   - Error: "You do not have permission to disable plugins. Required permission: plugins:disable"

5. **Load Plugin** (`loadPlugin`)
   - Required permission: `plugins:load`
   - Error: "You do not have permission to load plugins. Required permission: plugins:load"

6. **Unload Plugin** (`unloadPlugin`)
   - Required permission: `plugins:unload`
   - Error: "You do not have permission to unload plugins. Required permission: plugins:unload"

7. **Save Plugin Configuration** (`savePluginConfiguration`)
   - Required permission: `plugins:configure`
   - Error: "You do not have permission to configure plugins. Required permission: plugins:configure"

### 3. Enhanced Page Authorization

#### `isPluginPageAuthorized(pluginId: string, pagePath: string)`
Enhanced implementation that checks:
- User is authenticated
- Plugin exists and is installed
- Plugin is enabled and loaded
- User has `plugins:view` permission (if page requires auth)
- Respects the page's `requiresAuth` flag

### 4. UI Authorization Helpers

Added six convenience functions for UI components to check permissions:

1. **`canInstallPlugins()`**: Check if user can install new plugins
2. **`canUninstallPlugins()`**: Check if user can remove plugins
3. **`canEnablePlugins()`**: Check if user can enable plugins
4. **`canDisablePlugins()`**: Check if user can disable plugins
5. **`canConfigurePlugins()`**: Check if user can modify plugin configurations
6. **`canManagePlugins()`**: Check if user has any plugin management permissions

These helpers enable UI components to:
- Show/hide buttons and controls based on permissions
- Display appropriate permission warnings
- Conditionally render navigation items
- Provide better user experience by hiding unavailable features

## Permission System Details

### Permission Format
- **Exact permissions**: `plugins:install`, `plugins:enable`, etc.
- **Wildcard permissions**:
  - `plugins:*` - Grants all plugin permissions
  - `plugins:configure:*` - Grants all configuration permissions (if sub-namespaces exist)

### Role-Based Access
- **super_admin**: Full access to all plugin operations
- **admin**: Full access to all plugin operations
- **user**: Requires specific permissions in the `permissions` array

### Integration with Auth System
- Uses `useAuth()` from `/home/user/enclava/frontend/src/components/providers/auth-provider.tsx`
- Reads user role and permissions array from the authenticated user object
- Automatically denies all operations when not authenticated

## Files Modified

1. **`/home/user/enclava/frontend/src/contexts/PluginContext.tsx`**
   - Added comprehensive documentation header explaining the authorization system
   - Implemented `hasPermission()` and `checkPluginPermission()` functions
   - Added permission checks to all plugin action functions
   - Enhanced `isPluginPageAuthorized()` implementation
   - Added six UI helper functions for permission checking
   - Updated context interface to include authorization helpers
   - Updated SSR default values to include authorization helpers

## Files Created

1. **`/home/user/enclava/frontend/src/contexts/PluginContext.example.tsx`**
   - Comprehensive examples showing how to use authorization in UI components
   - Three example components demonstrating different use cases:
     - Conditional rendering based on permissions
     - Permission-based navigation
     - Handling permission errors
   - Documentation of permission requirements by action

2. **`/home/user/enclava/PLUGIN_AUTHORIZATION_IMPLEMENTATION.md`**
   - This summary document

## Usage Examples

### Example 1: Conditional Button Rendering
```typescript
import { usePlugin } from '@/contexts/PluginContext';

function PluginActions({ pluginId }) {
  const { enablePlugin, canEnablePlugins } = usePlugin();

  return (
    <>
      {canEnablePlugins() && (
        <button onClick={() => enablePlugin(pluginId)}>
          Enable Plugin
        </button>
      )}
    </>
  );
}
```

### Example 2: Permission Error Handling
```typescript
import { usePlugin } from '@/contexts/PluginContext';

function PluginInstaller() {
  const { installPlugin, error } = usePlugin();

  const handleInstall = async () => {
    const success = await installPlugin('my-plugin', '1.0.0');
    if (!success && error) {
      alert(error); // Shows: "You do not have permission to install plugins..."
    }
  };

  return <button onClick={handleInstall}>Install</button>;
}
```

### Example 3: Navigation Guard
```typescript
import { usePlugin } from '@/contexts/PluginContext';

function PluginMenu() {
  const { canManagePlugins, isPluginPageAuthorized } = usePlugin();

  return (
    <nav>
      {canManagePlugins() && (
        <Link href="/plugins">Plugin Management</Link>
      )}
      {isPluginPageAuthorized('analytics', '/dashboard') && (
        <Link href="/plugins/analytics/dashboard">Analytics</Link>
      )}
    </nav>
  );
}
```

## React/TypeScript Best Practices Applied

1. **Type Safety**: All functions have proper TypeScript type annotations
2. **useCallback**: Permission checking functions use useCallback for performance optimization
3. **Dependency Arrays**: All callbacks include proper dependency arrays
4. **Early Returns**: Permission checks fail fast with early returns
5. **Clear Error Messages**: All permission denials include descriptive error messages
6. **SSR Support**: Default values provided for server-side rendering scenarios
7. **Documentation**: Comprehensive JSDoc comments and inline documentation
8. **Separation of Concerns**: Authorization logic is separate from business logic
9. **DRY Principle**: Reusable permission checking functions prevent code duplication
10. **User Experience**: Helper functions make it easy for UI components to adapt to permissions

## Integration with Existing Components

The following existing plugin components can be updated to use the new authorization helpers:
- `/home/user/enclava/frontend/src/components/plugins/PluginNavigation.tsx`
- `/home/user/enclava/frontend/src/components/plugins/PluginManager.tsx`
- `/home/user/enclava/frontend/src/components/plugins/PluginConfigurationDialog.tsx`
- `/home/user/enclava/frontend/src/components/plugins/PluginPageRenderer.tsx`

## Backend Integration

The implementation integrates with the existing backend permission system:
- User permissions are stored in the `permissions` field (string array) in the User model
- Backend endpoints should validate permissions server-side
- Frontend authorization provides UX improvements and prevents unnecessary API calls
- Permission format matches backend schema: `namespace:action` (e.g., `plugins:install`)

## Security Considerations

1. **Client-side validation only**: This is frontend authorization for UX purposes
2. **Backend validation required**: Always validate permissions on the backend
3. **Defense in depth**: Frontend checks prevent UI clutter and improve UX, backend checks ensure security
4. **Error messages**: Clear but not overly verbose to avoid information leakage
5. **Role hierarchy**: Admin roles automatically have all permissions

## Testing Recommendations

To test the authorization system:

1. **As admin/super_admin**: All plugin operations should be available
2. **As user with no permissions**: All operations should be denied with appropriate error messages
3. **As user with specific permissions**: Only permitted operations should be available
4. **With wildcard permissions**: User with `plugins:*` should have access to all operations
5. **Page authorization**: Test that plugin pages respect the `requiresAuth` flag and permission checks
6. **UI helpers**: Verify that buttons and navigation items are shown/hidden correctly

## Next Steps (Optional)

1. Update existing plugin UI components to use the new authorization helpers
2. Add unit tests for permission checking functions
3. Add integration tests for the complete authorization flow
4. Consider adding permission logging for audit purposes
5. Document required permissions in plugin manifests
6. Create admin UI for managing user plugin permissions
