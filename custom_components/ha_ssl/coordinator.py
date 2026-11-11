"""Coordinator that watches the certificate and triggers renewals."""

from __future__ import annotations

import asyncio
import logging
from datetime import date

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .cert_manager import (
    CertInfo,
    CertIssueError,
    CertManager,
    async_apply_https_config,
    async_sync_external_url,
)
from .const import (
    CONF_AUTO_RENEW,
    CONF_EXPIRY_ALERT_DAYS,
    CONF_HTTPS_PORT,
    CONF_NOTIFY_WEBHOOK,
    CONF_RENEW_DAYS,
    CONF_RESTART_AFTER_RENEW,
    CONF_TLS_PROFILE,
    DEFAULT_AUTO_RENEW,
    DEFAULT_EXPIRY_ALERT_DAYS,
    DEFAULT_HTTPS_PORT,
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
        self._last_alert_day: date | None = None

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
            self.hass.async_create_task(
                self.hass.services.async_call(
                    "persistent_notification",
                    "create",
                    {
                        "title": "HA SSL 正在申请证书",
                        "notification_id": "ha_ssl_issuing",
                        "message": (
                            f"正在为 `{self.manager.domain}` 申请证书（DNS-01 验证），"
                            "通常 1–3 分钟完成，期间会自动写入 DNS 记录。"
                            "成功后证书保存到 /config/ssl，并自动启用 HTTPS。"
                        ),
                    },
                    blocking=False,
                )
            )
            # 首次签发时 ssl_certificate 还没写进 configuration.yaml，
            # 重启也不会让 HTTPS 生效，反而会打断用户，所以这里不重启。
            return await self._async_issue_once(restart_after=False)

        days_left = info.days_left
        await self._async_alert_if_due(info)
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
            await self._async_notify(
                "HA SSL · 证书签发/续期失败",
                f"域名 {self.manager.domain} 签发失败：{err}\n"
                "动态域名记录与凭据请先确认；证书到期前会继续重试。",
                notification_id="ha_ssl_issue_failed",
            )
            return info

        needs_restart = await self._async_align_https()
        if restart_after or needs_restart:
            await self._async_restart_ha()
        return info

    async def _async_align_https(self) -> bool:
        """Point HA's HTTP config at our certificate after a successful issue.

        Renewals keep the same path, but the configured path may still point at
        someone else's files (e.g. a previous DDNS tool), so realign every time.
        """
        options = self.entry.options
        try:
            result = await async_apply_https_config(
                self.hass,
                self.manager.fullchain_path,
                self.manager.key_path,
                port=int(options.get(CONF_HTTPS_PORT, DEFAULT_HTTPS_PORT) or 0) or None,
                tls_profile=str(options.get(CONF_TLS_PROFILE) or "") or None,
            )
        except Exception:  # noqa: BLE001
            _LOGGER.exception("证书已签发，但写入 HTTPS 配置失败")
            return False
        try:
            message = await async_sync_external_url(
                self.hass,
                self.manager.domain,
                int(options.get(CONF_HTTPS_PORT, DEFAULT_HTTPS_PORT) or 0) or None,
            )
        except Exception:  # noqa: BLE001
            _LOGGER.exception("更新 external_url 失败")
        else:
            if message:
                _LOGGER.info(message)
        if result.get("needs_restart"):
            _LOGGER.info("HTTPS 配置已对齐 /config/ssl，重启后生效")
            return True
        return False

    async def async_force_issue(self) -> CertInfo:
        """Issue immediately (button / service)."""
        info = await self.manager.async_issue()
        if await self._async_align_https():
            self.hass.async_create_task(self._async_restart_ha())
        self.async_set_updated_data(info)
        return info

    async def async_refresh_cert(self) -> CertInfo:
        """Re-read the certificate without touching the ACME server."""
        info = await self.hass.async_add_executor_job(self.manager.read_cert)
        self.async_set_updated_data(info)
        return info

    async def _async_alert_if_due(self, info: CertInfo) -> None:
        """Warn once a day when the certificate gets close to expiry."""
        options = self.entry.options
        threshold = int(
            options.get(CONF_EXPIRY_ALERT_DAYS, DEFAULT_EXPIRY_ALERT_DAYS)
        )
        if info.days_left is None or info.days_left > threshold:
            return
        today = date.today()
        if self._last_alert_day == today:
            return
        self._last_alert_day = today
        await self._async_notify(
            "HA SSL · 证书即将到期",
            f"域名 {self.manager.domain} 的证书还剩 {info.days_left} 天，"
            f"到期于 {info.valid_to.isoformat() if info.valid_to else '未知'}。\n"
            "若自动续期已开启，请检查最近一次签发日志。",
            notification_id="ha_ssl_expiring",
        )

    async def _async_notify(
        self, title: str, message: str, notification_id: str
    ) -> None:
        """Persistent notification plus an optional webhook."""
        await self.hass.services.async_call(
            "persistent_notification",
            "create",
            {"title": title, "notification_id": notification_id, "message": message},
            blocking=False,
        )
        self.hass.bus.async_fire(
            "ha_ssl_cert_alert",
            {"title": title, "message": message},
        )
        webhook = str(self.entry.options.get(CONF_NOTIFY_WEBHOOK) or "").strip()
        if not webhook.startswith(("http://", "https://")):
            return
        try:
            async with async_get_clientsession(self.hass).post(
                webhook,
                json={"title": title, "message": message, "domain": self.manager.domain},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status >= 400:
                    _LOGGER.warning("告警 Webhook 返回 HTTP %s", resp.status)
        except (aiohttp.ClientError, asyncio.TimeoutError) as err:
            _LOGGER.warning("告警 Webhook 发送失败：%s", err)

    async def _async_restart_ha(self) -> None:
        """Restart Home Assistant so the new certificate is loaded."""
        await asyncio.sleep(3)
        _LOGGER.info("证书已更新，重启 Home Assistant 以加载新证书")
        await self.hass.services.async_call(
            "homeassistant", "restart", {}, blocking=False
        )
