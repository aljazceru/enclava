/**
 * Example: Using Plugin Authorization in UI Components
 *
 * This file demonstrates how to use the plugin authorization system
 * to show/hide UI elements based on user permissions.
 */

import React from 'react';
import { usePlugin } from './PluginContext';

/**
 * Example 1: Conditional rendering based on permissions
 */
export const PluginManagementPanel: React.FC = () => {
  const {
    installedPlugins,
    canInstallPlugins,
    canEnablePlugins,
    canDisablePlugins,
    canConfigurePlugins,
    canUninstallPlugins,
    installPlugin,
    enablePlugin,
    disablePlugin,
  } = usePlugin();

  return (
    <div className="plugin-panel">
      <h2>Plugin Management</h2>

      {/* Only show install button if user has install permission */}
      {canInstallPlugins() && (
        <button onClick={() => installPlugin('example-plugin', '1.0.0')}>
          Install Plugin
        </button>
      )}

      {/* Plugin list with conditional action buttons */}
      {installedPlugins.map((plugin) => (
        <div key={plugin.id} className="plugin-item">
          <h3>{plugin.name}</h3>
          <p>{plugin.description}</p>

          {/* Enable/Disable buttons based on permissions */}
          {plugin.status === 'disabled' && canEnablePlugins() && (
            <button onClick={() => enablePlugin(plugin.id)}>Enable</button>
          )}

          {plugin.status === 'enabled' && canDisablePlugins() && (
            <button onClick={() => disablePlugin(plugin.id)}>Disable</button>
          )}

          {/* Configuration button */}
          {canConfigurePlugins() && (
            <button onClick={() => window.location.href = `/plugins/${plugin.id}/config`}>
              Configure
            </button>
          )}

          {/* Uninstall button */}
          {canUninstallPlugins() && (
            <button onClick={() => confirm('Uninstall?') && uninstallPlugin(plugin.id)}>
              Uninstall
            </button>
          )}
        </div>
      ))}
    </div>
  );
};

/**
 * Example 2: Using permissions for navigation
 */
export const PluginNavigation: React.FC = () => {
  const { canManagePlugins, isPluginPageAuthorized } = usePlugin();

  return (
    <nav>
      {/* Only show plugin management link if user can manage plugins */}
      {canManagePlugins() && (
        <a href="/plugins">Plugin Management</a>
      )}

      {/* Check if user can access specific plugin pages */}
      {isPluginPageAuthorized('example-plugin', '/dashboard') && (
        <a href="/plugins/example-plugin/dashboard">Plugin Dashboard</a>
      )}
    </nav>
  );
};

/**
 * Example 3: Handling permission errors
 */
export const PluginInstaller: React.FC = () => {
  const { installPlugin, canInstallPlugins, error } = usePlugin();
  const [selectedPlugin, setSelectedPlugin] = React.useState('');

  const handleInstall = async () => {
    // The installPlugin function will check permissions internally
    // and set the error state if permission is denied
    const success = await installPlugin(selectedPlugin, '1.0.0');

    if (!success && error) {
      alert(`Installation failed: ${error}`);
    }
  };

  return (
    <div>
      {canInstallPlugins() ? (
        <>
          <select onChange={(e) => setSelectedPlugin(e.target.value)}>
            <option value="">Select a plugin...</option>
            {/* Plugin options */}
          </select>
          <button onClick={handleInstall}>Install</button>
        </>
      ) : (
        <div className="permission-warning">
          You do not have permission to install plugins.
          Please contact your administrator.
        </div>
      )}
    </div>
  );
};

/**
 * Permission Requirements by Action:
 *
 * Install Plugin:
 *   - plugins:install OR plugins:* OR admin/super_admin role
 *
 * Uninstall Plugin:
 *   - plugins:uninstall OR plugins:* OR admin/super_admin role
 *
 * Enable Plugin:
 *   - plugins:enable OR plugins:* OR admin/super_admin role
 *
 * Disable Plugin:
 *   - plugins:disable OR plugins:* OR admin/super_admin role
 *
 * Configure Plugin:
 *   - plugins:configure OR plugins:* OR admin/super_admin role
 *
 * View Plugin Pages:
 *   - plugins:view OR plugins:* OR admin/super_admin role
 *   - Plugin must be enabled and loaded
 *
 * Manage Plugins (any operation):
 *   - Any of the above permissions OR plugins:manage OR plugins:* OR admin/super_admin role
 */
