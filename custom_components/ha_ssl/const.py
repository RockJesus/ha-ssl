"""Constants for the ACME certificate integration."""

from __future__ import annotations

import json
import pathlib
from datetime import timedelta

try:
    INTEGRATION_VERSION = json.loads(
        (pathlib.Path(__file__).parent / "manifest.json").read_text(encoding="utf-8")
    )["version"]
except (OSError, ValueError, KeyError):
    INTEGRATION_VERSION = ""

DOMAIN = "ha_ssl"
MANUFACTURER = "HA SSL"

# 配置项
CONF_DOMAIN = "domain"
CONF_PROVIDER = "provider"
CONF_CERT_DIR = "cert_dir"
CONF_STAGING = "staging"
CONF_AUTO_RENEW = "auto_renew"
CONF_RENEW_DAYS = "renew_days"
CONF_RESTART_AFTER_RENEW = "restart_after_renew"
CONF_RESTART = "restart"

# 服务商凭据
CONF_ALIYUN_ACCESS_KEY_ID = "aliyun_access_key_id"
CONF_ALIYUN_ACCESS_KEY_SECRET = "aliyun_access_key_secret"
CONF_DNSPOD_TOKEN_ID = "dnspod_token_id"
CONF_DNSPOD_TOKEN = "dnspod_token"
CONF_CLOUDFLARE_API_TOKEN = "cloudflare_api_token"

# 服务商标识
PROVIDER_ALIYUN = "aliyun"
PROVIDER_DNSPOD = "dnspod"
PROVIDER_CLOUDFLARE = "cloudflare"
PROVIDER_OPTIONS = (PROVIDER_ALIYUN, PROVIDER_DNSPOD, PROVIDER_CLOUDFLARE)

# 默认值
DEFAULT_CERT_DIR = "/config/ssl"
FALLBACK_CERT_DIR = "/config/ssl"
DEFAULT_RENEW_DAYS = 30
DEFAULT_AUTO_RENEW = True
DEFAULT_RESTART_AFTER_RENEW = True
DEFAULT_STAGING = False
DEFAULT_WAIT_TIMEOUT = 300
DEFAULT_UPDATE_INTERVAL = timedelta(hours=6)

CERT_FILE_NAME = "fullchain.pem"
KEY_FILE_NAME = "privkey.pem"
ACCOUNT_KEY_DIR = "/config/ha_ssl"
ACCOUNT_KEY_FILE = "account_key.pem"
STATE_FILE = "state.json"

# ACME
ACME_DIRECTORY_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
ACME_DIRECTORY_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
ACME_USER_AGENT = "home-assistant-ha-ssl"

# 阿里云 DNS
ALIYUN_DNS_ENDPOINT = "https://dns.aliyuncs.com/"
ALIYUN_DNS_VERSION = "2015-01-09"
ALIYUN_API_TIMEOUT = 20

# 腾讯云 DNSPod / Cloudflare
DNSPOD_ENDPOINT = "https://dnsapi.cn/"
CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
PROVIDER_API_TIMEOUT = 20

# DNS over HTTPS，用公共解析器验证 TXT 是否生效，不受本机解析器影响
DOH_RESOLVERS = (
    "https://223.5.5.5/resolve",
    "https://dns.alidns.com/resolve",
    "https://dns.google/resolve",
)

# 服务
SERVICE_RENEW = "renew"
SERVICE_CONFIGURE_HTTPS = "configure_https"
SERVICE_PROBE = "probe"
ATTR_RESTART = "restart"

# 平台
PLATFORMS = ["sensor", "binary_sensor", "button", "switch"]
