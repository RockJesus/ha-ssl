"""Config flow for the ACME certificate integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.core import HomeAssistant
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    ACME_DIRECTORY_PRODUCTION,
    ACME_DIRECTORY_STAGING,
    CONF_ACCESS_KEY_ID,
    CONF_ACCESS_KEY_SECRET,
    CONF_AUTO_RENEW,
    CONF_CERT_DIR,
    CONF_DOMAIN,
    CONF_EMAIL,
    CONF_RENEW_DAYS,
    CONF_RESTART_AFTER_RENEW,
    CONF_STAGING,
    DEFAULT_AUTO_RENEW,
    DEFAULT_CERT_DIR,
    DEFAULT_RENEW_DAYS,
    DEFAULT_RESTART_AFTER_RENEW,
    DOMAIN,
)
from .dns_aliyun import AliyunDnsClient, AliyunDnsError

_LOGGER = logging.getLogger(__name__)


async def _async_validate_user_input(
    hass: HomeAssistant, user_input: dict[str, Any]
) -> None:
    """Validate the Aliyun credentials and the domain ownership."""
    session = async_get_clientsession(hass)
    client = AliyunDnsClient(
        session,
        str(user_input[CONF_ACCESS_KEY_ID]),
        str(user_input[CONF_ACCESS_KEY_SECRET]),
    )
    await client.async_find_zone(str(user_input[CONF_DOMAIN]))


class AcmeCertConfigFlow(ConfigFlow, domain=DOMAIN):
    """Ask for the domain, contact email and Aliyun credentials."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            domain = str(user_input[CONF_DOMAIN]).strip().lower()
            try:
                await _async_validate_user_input(self.hass, user_input)
            except AliyunDnsError as err:
                _LOGGER.error("校验阿里云凭据失败：%s", err)
                errors["base"] = "invalid_auth"
            except Exception:  # noqa: BLE001
                _LOGGER.exception("校验阿里云凭据时出现异常")
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(domain)
                self._abort_if_unique_id_configured()
                user_input[CONF_DOMAIN] = domain
                return self.async_create_entry(title=domain, data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_DOMAIN): str,
                    vol.Required(CONF_EMAIL): str,
                    vol.Required(CONF_ACCESS_KEY_ID): str,
                    vol.Required(CONF_ACCESS_KEY_SECRET): str,
                    vol.Optional(CONF_CERT_DIR, default=DEFAULT_CERT_DIR): str,
                    vol.Optional(CONF_STAGING, default=False): bool,
                }
            ),
            errors=errors,
            description_placeholders={
                "production": ACME_DIRECTORY_PRODUCTION,
                "staging": ACME_DIRECTORY_STAGING,
            },
        )

    @staticmethod
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Return the options flow."""
        return AcmeCertOptionsFlow()


class AcmeCertOptionsFlow(OptionsFlow):
    """Tune renewal behaviour."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_AUTO_RENEW,
                        default=options.get(CONF_AUTO_RENEW, DEFAULT_AUTO_RENEW),
                    ): bool,
                    vol.Optional(
                        CONF_RENEW_DAYS,
                        default=options.get(CONF_RENEW_DAYS, DEFAULT_RENEW_DAYS),
                    ): selector.NumberSelector(
                        selector.NumberSelectorConfig(
                            min=7,
                            max=89,
                            step=1,
                            mode=selector.NumberSelectorMode.BOX,
                            unit_of_measurement="天",
                        )
                    ),
                    vol.Optional(
                        CONF_RESTART_AFTER_RENEW,
                        default=options.get(
                            CONF_RESTART_AFTER_RENEW, DEFAULT_RESTART_AFTER_RENEW
                        ),
                    ): bool,
                }
            ),
        )
