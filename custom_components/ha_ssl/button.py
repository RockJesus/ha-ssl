"""Button that issues or renews the certificate on demand."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .cert_manager import (
    CertIssueError,
    async_apply_https_config,
    async_sync_external_url,
)
from .const import CONF_HTTPS_PORT, CONF_TLS_PROFILE, DOMAIN
from .coordinator import AcmeCertCoordinator
from .sensor import _CertBaseEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the issue button."""
    coordinator: AcmeCertCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([IssueButton(coordinator), SyncHttpsButton(coordinator)])


class IssueButton(_CertBaseEntity, ButtonEntity):
    """Run a dns-01 issuance immediately."""

    _attr_translation_key = "issue"
    _attr_icon = "mdi:certificate-outline"

    def __init__(self, coordinator: AcmeCertCoordinator) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_issue"

    async def async_press(self) -> None:
        """Issue the certificate."""
        if self.coordinator.manager.busy:
            raise HomeAssistantError("已有一签发任务在运行，请稍后再试")
        try:
            await self.coordinator.async_force_issue()
        except CertIssueError as err:
            raise HomeAssistantError(f"签发失败：{err}") from err


class SyncHttpsButton(_CertBaseEntity, ButtonEntity):
    """Write this entry's certificate and port into HA's HTTP settings."""

    _attr_translation_key = "sync_https"
    _attr_icon = "mdi:sync"

    def __init__(self, coordinator: AcmeCertCoordinator) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.entry.entry_id}_sync_https"

    async def async_press(self) -> None:
        """Apply the certificate + port, then ask the user to restart."""
        manager = self.coordinator.manager
        options = self.coordinator.entry.options
        try:
            result = await async_apply_https_config(
                self.hass,
                manager.fullchain_path,
                manager.key_path,
                port=options.get(CONF_HTTPS_PORT),
                tls_profile=options.get(CONF_TLS_PROFILE),
            )
            synced = await async_sync_external_url(
                self.hass, manager.domain, options.get(CONF_HTTPS_PORT)
            )
        except Exception as err:  # noqa: BLE001 - surface it to the UI
            raise HomeAssistantError(f"同步 HTTP 设置失败：{err}") from err

        need_restart = bool(result.get("needs_restart"))
        message = str(result.get("message") or "已检查 HTTP 设置")
        if synced:
            message = f"{message}；{synced}"
        body = (
            f"{message}。\n\n请到「设置 → 系统 → 右上角电源菜单 → 重启 Home Assistant」"
            "让新配置生效（集成不会自动重启）。"
            if need_restart
            else f"{message}，当前配置已一致，无需重启。"
        )
        await self.hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": "HA SSL：HTTP 设置同步完成",
                "notification_id": "ha_ssl_sync_https",
                "message": body,
            },
            blocking=False,
        )
