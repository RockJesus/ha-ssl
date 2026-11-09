"""Button that issues or renews the certificate on demand."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .cert_manager import CertIssueError
from .const import DOMAIN
from .coordinator import AcmeCertCoordinator
from .sensor import _CertBaseEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the issue button."""
    coordinator: AcmeCertCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([IssueButton(coordinator)])


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
