"""
Plugin Registry API Endpoints
Provides REST API for plugin management, discovery, and installation
"""
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.services.plugin_registry import plugin_installer, plugin_discovery
from app.services.plugin_sandbox import plugin_loader
from app.services.plugin_context_manager import plugin_context_manager
from app.core.logging import get_logger


logger = get_logger("plugin.registry.api")
router = APIRouter()


# Pydantic models for request/response
class PluginSearchRequest(BaseModel):
    query: str = ""
    tags: Optional[List[str]] = None
    category: Optional[str] = None
    limit: int = 20


class PluginInstallRequest(BaseModel):
    plugin_id: str
    version: str
    source: str = "repository"  # "repository" or "file"


class PluginUninstallRequest(BaseModel):
    keep_data: bool = True


# Discovery endpoints
@router.get("/discover")
async def discover_plugins(
    query: str = "",
    tags: str = "",
    category: str = "",
    limit: int = 20,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Discover available plugins from repository"""
    try:
        tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()] if tags else None
        
        plugins = await plugin_discovery.search_available_plugins(
            query=query,
            tags=tag_list, 
            category=category if category else None,
            limit=limit,
            db=db
        )
        
        return {
            "plugins": plugins,
            "count": len(plugins),
            "query": query,
            "filters": {
                "tags": tag_list,
                "category": category
            }
        }
        
    except Exception as e:
        logger.error(f"Plugin discovery failed: {e}")
        raise HTTPException(status_code=500, detail=f"Discovery failed: {e}")


@router.get("/categories")
async def get_plugin_categories(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Get available plugin categories"""
    try:
        categories = await plugin_discovery.get_plugin_categories()
        return {"categories": categories}
        
    except Exception as e:
        logger.error(f"Failed to get categories: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get categories: {e}")



@router.get("/installed")
async def get_installed_plugins(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get user's installed plugins"""
    try:
        plugins = await plugin_discovery.get_installed_plugins(current_user["id"], db)
        return {
            "plugins": plugins,
            "count": len(plugins)
        }
        
    except Exception as e:
        logger.error(f"Failed to get installed plugins: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get installed plugins: {e}")


@router.get("/updates")
async def check_plugin_updates(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Check for available plugin updates"""
    try:
        updates = await plugin_discovery.get_plugin_updates(db)
        return {
            "updates": updates,
            "count": len(updates)
        }
        
    except Exception as e:
        logger.error(f"Failed to check updates: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to check updates: {e}")


# Installation endpoints
@router.post("/install")
async def install_plugin(
    request: PluginInstallRequest,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Install plugin from repository"""
    try:
        if request.source != "repository":
            raise HTTPException(status_code=400, detail="Only repository installation supported via this endpoint")
        
        # Start installation in background
        background_tasks.add_task(
            install_plugin_background,
            request.plugin_id,
            request.version,
            current_user["id"],
            db
        )
        
        return {
            "status": "installation_started",
            "plugin_id": request.plugin_id,
            "version": request.version,
            "message": "Plugin installation started in background"
        }
        
    except Exception as e:
        logger.error(f"Plugin installation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Installation failed: {e}")


@router.post("/install/upload")
async def install_plugin_from_file(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Install plugin from uploaded file"""
    try:
        # Validate file type
        if not file.filename.endswith('.zip'):
            raise HTTPException(status_code=400, detail="Only ZIP files are supported")
        
        # Save uploaded file
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = temp_file.name
        
        try:
            # Install plugin
            result = await plugin_installer.install_plugin_from_file(
                temp_file_path, current_user["id"], db
            )
            
            return {
                "status": "installed",
                "result": result,
                "message": "Plugin installed successfully"
            }
            
        finally:
            # Cleanup temp file
            import os
            os.unlink(temp_file_path)
            
    except Exception as e:
        logger.error(f"File upload installation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Installation failed: {e}")


@router.delete("/{plugin_id}")
async def uninstall_plugin(
    plugin_id: str,
    request: PluginUninstallRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Uninstall plugin"""
    try:
        result = await plugin_installer.uninstall_plugin(
            plugin_id, current_user["id"], db, request.keep_data
        )
        
        return {
            "status": "uninstalled",
            "result": result,
            "message": "Plugin uninstalled successfully"
        }
        
    except Exception as e:
        logger.error(f"Plugin uninstall failed: {e}")
        raise HTTPException(status_code=500, detail=f"Uninstall failed: {e}")


# Plugin management endpoints
@router.post("/{plugin_id}/enable")
async def enable_plugin(
    plugin_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Enable plugin"""
    try:
        from app.models.plugin import Plugin
        from sqlalchemy import select
        
        stmt = select(Plugin).where(Plugin.id == plugin_id)
        result = await db.execute(stmt)
        plugin = result.scalar_one_or_none()
        if not plugin:
            raise HTTPException(status_code=404, detail="Plugin not found")
        
        plugin.status = "enabled"
        await db.commit()
        
        return {
            "status": "enabled",
            "plugin_id": plugin_id,
            "message": "Plugin enabled successfully"
        }
        
    except Exception as e:
        logger.error(f"Plugin enable failed: {e}")
        raise HTTPException(status_code=500, detail=f"Enable failed: {e}")


@router.post("/{plugin_id}/disable")
async def disable_plugin(
    plugin_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Disable plugin"""
    try:
        from app.models.plugin import Plugin
        from sqlalchemy import select
        
        stmt = select(Plugin).where(Plugin.id == plugin_id)
        result = await db.execute(stmt)
        plugin = result.scalar_one_or_none()
        if not plugin:
            raise HTTPException(status_code=404, detail="Plugin not found")
        
        # Unload if currently loaded
        if plugin_id in plugin_loader.loaded_plugins:
            await plugin_loader.unload_plugin(plugin_id)
        
        plugin.status = "disabled"
        await db.commit()
        
        return {
            "status": "disabled", 
            "plugin_id": plugin_id,
            "message": "Plugin disabled successfully"
        }
        
    except Exception as e:
        logger.error(f"Plugin disable failed: {e}")
        raise HTTPException(status_code=500, detail=f"Disable failed: {e}")


@router.post("/{plugin_id}/load")
async def load_plugin(
    plugin_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Load plugin into runtime"""
    try:
        from app.models.plugin import Plugin
        from pathlib import Path
        from sqlalchemy import select
        
        stmt = select(Plugin).where(Plugin.id == plugin_id)
        result = await db.execute(stmt)
        plugin = result.scalar_one_or_none()
        if not plugin:
            raise HTTPException(status_code=404, detail="Plugin not found")
        
        if plugin.status != "enabled":
            raise HTTPException(status_code=400, detail="Plugin must be enabled to load")
        
        if plugin_id in plugin_loader.loaded_plugins:
            raise HTTPException(status_code=400, detail="Plugin already loaded")
        
        # Load plugin with proper context management
        plugin_dir = Path(plugin.plugin_dir)
        
        # Create plugin context for standardized interface
        plugin_context = plugin_context_manager.create_plugin_context(
            plugin_id=plugin_id,
            user_id=str(current_user.get("id", "unknown")),  # Use actual user ID
            session_type="api_load"
        )
        
        # Generate plugin token based on context
        plugin_token = plugin_context_manager.generate_plugin_token(plugin_context["context_id"])
        
        # Log plugin loading action
        plugin_context_manager.add_audit_trail_entry(
            plugin_context["context_id"],
            "plugin_load_via_api",
            {
                "plugin_dir": str(plugin_dir), 
                "user_id": current_user.get("id", "unknown"),
                "action": "load_plugin_with_sandbox"
            }
        )
        
        await plugin_loader.load_plugin_with_sandbox(plugin_dir, plugin_token)
        
        return {
            "status": "loaded",
            "plugin_id": plugin_id,
            "message": "Plugin loaded successfully"
        }
        
    except Exception as e:
        logger.error(f"Plugin load failed: {e}")
        raise HTTPException(status_code=500, detail=f"Load failed: {e}")


@router.post("/{plugin_id}/unload")
async def unload_plugin(
    plugin_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Unload plugin from runtime"""
    try:
        if plugin_id not in plugin_loader.loaded_plugins:
            raise HTTPException(status_code=404, detail="Plugin not loaded")
        
        success = await plugin_loader.unload_plugin(plugin_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to unload plugin")
        
        return {
            "status": "unloaded",
            "plugin_id": plugin_id,
            "message": "Plugin unloaded successfully"
        }
        
    except Exception as e:
        logger.error(f"Plugin unload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Unload failed: {e}")


# Configuration endpoints
@router.get("/{plugin_id}/config")
async def get_plugin_configuration(
    plugin_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get plugin configuration for user with automatic decryption"""
    try:
        from app.services.plugin_configuration_manager import plugin_config_manager
        
        # Use the new configuration manager to get decrypted configuration
        config_data = await plugin_config_manager.get_plugin_configuration(
            plugin_id=plugin_id,
            user_id=current_user["id"],
            db=db,
            decrypt_sensitive=False  # Don't decrypt sensitive data for API response
        )
        
        if config_data is not None:
            return {
                "plugin_id": plugin_id,
                "configuration": config_data,
                "has_configuration": True
            }
        else:
            # Get default configuration from manifest
            resolved_config = await plugin_config_manager.get_resolved_configuration(
                plugin_id=plugin_id,
                user_id=current_user["id"],
                db=db
            )
            
            return {
                "plugin_id": plugin_id,
                "configuration": resolved_config,
                "has_configuration": False
            }
            
    except Exception as e:
        logger.error(f"Failed to get plugin configuration: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get configuration: {e}")


@router.post("/{plugin_id}/config")
async def save_plugin_configuration(
    plugin_id: str,
    config_request: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Save plugin configuration for user with automatic encryption of sensitive fields"""
    try:
        from app.services.plugin_configuration_manager import plugin_config_manager
        
        # Extract configuration data and metadata
        config_data = config_request.get("configuration", {})
        config_name = config_request.get("name", "Default Configuration")
        config_description = config_request.get("description")
        
        # Use the new configuration manager to save with automatic encryption
        saved_config = await plugin_config_manager.save_plugin_configuration(
            plugin_id=plugin_id,
            user_id=current_user["id"],
            config_data=config_data,
            config_name=config_name,
            config_description=config_description,
            db=db
        )
        
        return {
            "status": "saved",
            "plugin_id": plugin_id,
            "configuration_id": str(saved_config.id),
            "message": "Configuration saved successfully with automatic encryption of sensitive fields"
        }
        
    except Exception as e:
        logger.error(f"Failed to save plugin configuration: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to save configuration: {e}")


@router.get("/{plugin_id}/schema")
async def get_plugin_configuration_schema(
    plugin_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get plugin configuration schema from manifest"""
    try:
        from app.services.plugin_configuration_manager import plugin_config_manager
        
        # Use the new configuration manager to get schema
        schema = await plugin_config_manager.get_plugin_configuration_schema(plugin_id, db)
        
        if not schema:
            raise HTTPException(status_code=404, detail=f"No configuration schema available for plugin '{plugin_id}'")
        
        return {
            "plugin_id": plugin_id,
            "schema": schema
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get plugin schema: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get schema: {str(e)}")


@router.get("/notifications")
async def get_plugin_notifications(
    current_user: Dict[str, Any] = Depends(get_current_user),
    unread_only: bool = False,
    db: AsyncSession = Depends(get_db)
):
    """Get plugin-related notifications for the current user"""
    try:
        from app.models.user import User
        from sqlalchemy import select

        # Get user with notification settings
        user_stmt = select(User).where(User.id == current_user["id"])
        user_result = await db.execute(user_stmt)
        user = user_result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Get plugin notifications
        notifications = []
        if user.notification_settings and "plugin_notifications" in user.notification_settings:
            notifications = user.notification_settings["plugin_notifications"]

            # Filter for unread only if requested
            if unread_only:
                notifications = [n for n in notifications if not n.get("read", False)]

        return {
            "notifications": notifications,
            "count": len(notifications),
            "unread_count": len([n for n in notifications if not n.get("read", False)])
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get plugin notifications: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get notifications: {e}")


@router.post("/notifications/{notification_index}/mark-read")
async def mark_notification_read(
    notification_index: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Mark a plugin notification as read"""
    try:
        from app.models.user import User
        from sqlalchemy import select

        # Get user with notification settings
        user_stmt = select(User).where(User.id == current_user["id"])
        user_result = await db.execute(user_stmt)
        user = user_result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Mark notification as read
        if user.notification_settings and "plugin_notifications" in user.notification_settings:
            notifications = user.notification_settings["plugin_notifications"]

            if 0 <= notification_index < len(notifications):
                notifications[notification_index]["read"] = True
                await db.commit()

                return {
                    "status": "success",
                    "message": "Notification marked as read"
                }
            else:
                raise HTTPException(status_code=404, detail="Notification not found")
        else:
            raise HTTPException(status_code=404, detail="No notifications found")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to mark notification as read: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to mark notification as read: {e}")


@router.post("/{plugin_id}/test-credentials")
async def test_plugin_credentials(
    plugin_id: str,
    test_request: Dict[str, Any],
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Test plugin credentials (currently supports Zammad)"""
    import httpx
    
    try:
        logger.info(f"Testing credentials for plugin {plugin_id}")
        
        # Get plugin from database to check its name
        from app.models.plugin import Plugin
        from sqlalchemy import select
        
        stmt = select(Plugin).where(Plugin.id == plugin_id)
        result = await db.execute(stmt)
        plugin = result.scalar_one_or_none()
        
        if not plugin:
            raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found")
        
        # Check if this is a Zammad plugin
        if plugin.name.lower() != 'zammad':
            raise HTTPException(status_code=400, detail=f"Credential testing not supported for plugin '{plugin.name}'")
        
        # Extract credentials from request
        zammad_url = test_request.get('zammad_url')
        api_token = test_request.get('api_token')
        
        if not zammad_url or not api_token:
            raise HTTPException(status_code=400, detail="Both zammad_url and api_token are required")
        
        # Clean up the URL (remove trailing slash)
        zammad_url = zammad_url.rstrip('/')
        
        # Test credentials by making a read-only API call to Zammad
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try to get user info - this is a safe read-only operation
            test_url = f"{zammad_url}/api/v1/users/me"
            headers = {
                'Authorization': f'Token token={api_token}',
                'Content-Type': 'application/json'
            }
            
            response = await client.get(test_url, headers=headers)
            
            if response.status_code == 200:
                # Success - credentials are valid
                user_data = response.json()
                user_email = user_data.get('email', 'unknown')
                return {
                    "success": True,
                    "message": f"Credentials verified! Connected as: {user_email}",
                    "zammad_url": zammad_url,
                    "user_info": {
                        "email": user_email,
                        "firstname": user_data.get('firstname', ''),
                        "lastname": user_data.get('lastname', '')
                    }
                }
            elif response.status_code == 401:
                return {
                    "success": False,
                    "message": "Invalid API token. Please check your token and try again.",
                    "error_code": "invalid_token"
                }
            elif response.status_code == 404:
                return {
                    "success": False,
                    "message": "Zammad URL not found. Please verify the URL is correct.",
                    "error_code": "invalid_url"
                }
            else:
                error_text = ""
                try:
                    error_data = response.json()
                    error_text = error_data.get('error', error_data.get('message', ''))
                except:
                    error_text = response.text[:200]
                
                return {
                    "success": False,
                    "message": f"Connection failed (HTTP {response.status_code}): {error_text}",
                    "error_code": "connection_failed"
                }
    
    except httpx.TimeoutException:
        return {
            "success": False,
            "message": "Connection timeout. Please check the Zammad URL and your network connection.",
            "error_code": "timeout"
        }
    except httpx.ConnectError:
        return {
            "success": False,
            "message": "Could not connect to Zammad. Please verify the URL is correct and accessible.",
            "error_code": "connection_error"
        }
    except Exception as e:
        logger.error(f"Failed to test plugin credentials: {e}")
        return {
            "success": False,
            "message": f"Test failed: {str(e)}",
            "error_code": "unknown_error"
        }


# Background task for plugin installation
async def install_plugin_background(plugin_id: str, version: str, user_id: str, db: AsyncSession):
    """Background task for plugin installation"""
    try:
        result = await plugin_installer.install_plugin_from_repository(
            plugin_id, version, user_id, db
        )
        logger.info(f"Background installation completed: {result}")

        # Create success audit log
        from app.models.plugin import PluginAuditLog
        from datetime import datetime, timezone

        audit_log = PluginAuditLog(
            plugin_id=plugin_id,
            user_id=user_id,
            action="install",
            event_type="installation_success",
            resource=f"plugin/{plugin_id}",
            success=True,
            request_data={"version": version, "source": "repository"},
            response_data=result,
            timestamp=datetime.now(timezone.utc)
        )
        db.add(audit_log)
        await db.commit()

    except Exception as e:
        logger.error(f"Background installation failed for plugin {plugin_id}: {e}")

        # Create failure audit log with error details
        from app.models.plugin import PluginAuditLog
        from app.models.user import User
        from sqlalchemy import select
        from datetime import datetime, timezone

        try:
            # Create detailed audit log for the failure
            audit_log = PluginAuditLog(
                plugin_id=plugin_id,
                user_id=user_id,
                action="install",
                event_type="installation_failure",
                resource=f"plugin/{plugin_id}",
                success=False,
                error_message=str(e),
                request_data={"version": version, "source": "repository"},
                timestamp=datetime.now(timezone.utc)
            )
            db.add(audit_log)

            # Update user notification settings to notify about the failure
            user_stmt = select(User).where(User.id == user_id)
            user_result = await db.execute(user_stmt)
            user = user_result.scalar_one_or_none()

            if user:
                # Add notification to user's notification settings
                if not user.notification_settings:
                    user.notification_settings = {}

                if "plugin_notifications" not in user.notification_settings:
                    user.notification_settings["plugin_notifications"] = []

                # Add installation failure notification
                notification = {
                    "type": "plugin_installation_failure",
                    "plugin_id": plugin_id,
                    "version": version,
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "read": False
                }

                user.notification_settings["plugin_notifications"].append(notification)

                # Keep only last 50 notifications
                if len(user.notification_settings["plugin_notifications"]) > 50:
                    user.notification_settings["plugin_notifications"] = user.notification_settings["plugin_notifications"][-50:]

                logger.info(f"Added installation failure notification for user {user_id}")

            await db.commit()

        except Exception as notification_error:
            logger.error(f"Failed to create installation failure notification: {notification_error}")
            await db.rollback()