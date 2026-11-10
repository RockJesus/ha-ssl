"""Coordinator that watches the certificate and triggers renewals."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .cert_manager import CertInfo, CertIssueError, CertManager
from .const import (
    CONF_AUTO_RENEW,
    CONF_RENEW_DAYS,
    CONF_RESTART_AFTER_RENEW,
    DEFAULT_AUTO_RENEW,
    DEFAULT_RENEW_DAYS,
    DEFAULT_RESTART_AFTER_RENEW,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


class AcmeCertCoordinator(DataUpdateCoordinator[CertInfo]):
    """Poll the certificate file every few hours and renew when due."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        manager: CertManager,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}:{entry.data.get('domain', entry.entry_id)}",
            update_interval=DEFAULT_UPDATE_INTERVAL,
            config_entry=entry,
        )
        self.entry = entry
        self.manager = manager
        self._first_run = True

    async def _async_update_data(self) -> CertInfo:
        """Read the certificate and renew it when it is close to expiry."""
        info = await self.hass.async_add_executor_job(self.manager.read_cert)

        options = self.entry.options
        auto_renew = bool(options.get(CONF_AUTO_RENEW, DEFAULT_AUTO_RENEW))
        renew_days = int(options.get(CONF_RENEW_DAYS, DEFAULT_RENEW_DAYS))

        if self._first_run:
            # Never block startup with a full issuance; the delayed refresh
            # scheduled during setup will handle the first issuance.
            self._first_run = False
            return info

        if not info.exists or info.valid_to is None:
            if not auto_renew or self.manager.busy:
                return info
            _LOGGER.info("还没有证书，开始首次签发：%s", self.manager.domain)
            # 首次签发时 ssl_certificate 还没写进 configuration.yaml，
            # 重启也不会让 HTTPS 生效，反而会打断用户，所以这里不重启。
            return await self._async_issue_once(restart_after=False)

        days_left = info.days_left
        if (
            auto_renew
            and not self.manager.busy
            and days_left is not None
            and days_left <= renew_days
        ):
            _LOGGER.info(
                "证书剩余 %s 天，开始自动续期（阈值 %s 天）", days_left, renew_days
            )
            should_restart = bool(
                options.get(CONF_RESTART_AFTER_RENEW, DEFAULT_RESTART_AFTER_RENEW)
            )
            return await self._async_issue_once(restart_after=should_restart)

        return info

    async def _async_issue_once(self, *, restart_after: bool) -> CertInfo:
        """Run one issuance and keep the last error visible on failure."""
        try:
            info = await self.manager.async_issue()
        except CertIssueError as err:
            _LOGGER.error("签发失败：%s", err)
            info = await self.hass.async_add_executor_job(self.manager.read_cert)
            info.last_error = str(err)
            return info

        if restart_after:
            await self._async_restart_ha()
        return info

    async def async_force_issue(self) -> CertInfo:
        """Issue immediately (button / service)."""
        info = await self.manager.async_issue()
        self.async_set_updated_data(info)
        return info

    async def async_refresh_cert(self) -> CertInfo:
        """Re-read the certificate without touching the ACME server."""
        info = await self.hass.async_add_executor_job(self.manager.read_cert)
        self.async_set_updated_data(info)
        return info

    async def _async_restart_ha(self) -> None:
        """Restart Home Assistant so the new certificate is loaded."""
        await asyncio.sleep(3)
        _LOGGER.info("证书已更新，重启 Home Assistant 以加载新证书")
        await self.hass.services.async_call(
            "homeassistant", "restart", {}, blocking=False
        )
