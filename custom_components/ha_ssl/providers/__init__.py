"""DNS provider registry: pick the implementation from the config entry."""

from __future__ import annotations

from typing import Any

import aiohttp

from ..const import (
    CONF_ALIYUN_ACCESS_KEY_ID,
    CONF_ALIYUN_ACCESS_KEY_SECRET,
    CONF_CLOUDFLARE_API_TOKEN,
    CONF_DNSPOD_TOKEN,
    CONF_DNSPOD_TOKEN_ID,
    PROVIDER_ALIYUN,
    PROVIDER_CLOUDFLARE,
    PROVIDER_DNSPOD,
)
from .aliyun import AliyunProvider
from .base import DnsProvider, DnsProviderError
from .cloudflare import CloudflareProvider
from .dnspod import DnspodProvider

PROVIDER_CLASSES: dict[str, str] = {
    PROVIDER_ALIYUN: "阿里云云解析",
    PROVIDER_DNSPOD: "腾讯云 DNSPod",
    PROVIDER_CLOUDFLARE: "Cloudflare",
}


def async_create_provider(
    session: aiohttp.ClientSession, provider: str, data: dict[str, Any]
) -> DnsProvider:
    """Instantiate the provider selected in the config entry."""
    if provider == PROVIDER_ALIYUN:
        return AliyunProvider(
            session,
            str(data[CONF_ALIYUN_ACCESS_KEY_ID]),
            str(data[CONF_ALIYUN_ACCESS_KEY_SECRET]),
        )
    if provider == PROVIDER_DNSPOD:
        return DnspodProvider(
            session,
            str(data[CONF_DNSPOD_TOKEN_ID]),
            str(data[CONF_DNSPOD_TOKEN]),
        )
    if provider == PROVIDER_CLOUDFLARE:
        return CloudflareProvider(session, str(data[CONF_CLOUDFLARE_API_TOKEN]))

    raise DnsProviderError(f"不支持的 DNS 服务商：{provider}")


__all__ = [
    "PROVIDER_CLASSES",
    "async_create_provider",
    "AliyunProvider",
    "CloudflareProvider",
    "DnspodProvider",
    "DnsProvider",
    "DnsProviderError",
]
