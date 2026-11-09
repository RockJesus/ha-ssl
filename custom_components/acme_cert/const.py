"""Constants for the ACME certificate integration."""

from __future__ import annotations

from datetime import timedelta

DOMAIN = "acme_cert"
MANUFACTURER = "ACME"

# 配置项
CONF_DOMAIN = "domain"
CONF_EMAIL = "email"
CONF_ACCESS_KEY_ID = "access_key_id"
CONF_ACCESS_KEY_SECRET = "access_key_secret"
CONF_CERT_DIR = "cert_dir"
CONF_STAGING = "staging"
CONF_AUTO_RENEW = "auto_renew"
CONF_RENEW_DAYS = "renew_days"
CONF_RESTART_AFTER_RENEW = "restart_after_renew"
CONF_RESTART = "restart"

# 默认值
DEFAULT_CERT_DIR = "/ssl"
DEFAULT_RENEW_DAYS = 30
DEFAULT_AUTO_RENEW = True
DEFAULT_RESTART_AFTER_RENEW = True
DEFAULT_STAGING = False
DEFAULT_WAIT_TIMEOUT = 300
DEFAULT_UPDATE_INTERVAL = timedelta(hours=6)

CERT_FILE_NAME = "fullchain.pem"
KEY_FILE_NAME = "privkey.pem"
ACCOUNT_KEY_DIR = "/config/acme_cert"
ACCOUNT_KEY_FILE = "account_key.pem"
STATE_FILE = "state.json"

# ACME
ACME_DIRECTORY_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
ACME_DIRECTORY_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"
ACME_USER_AGENT = "home-assistant-acme-cert"

# 阿里云 DNS
ALIYUN_DNS_ENDPOINT = "https://dns.aliyuncs.com/"
ALIYUN_DNS_VERSION = "2015-01-09"
ALIYUN_API_TIMEOUT = 20

# DNS over HTTPS，用公共解析器验证 TXT 是否生效，不受本机解析器影响
DOH_RESOLVERS = (
    "https://223.5.5.5/resolve",
    "https://dns.alidns.com/resolve",
    "https://dns.google/resolve",
)

# 服务
SERVICE_RENEW = "renew"
SERVICE_CONFIGURE_HTTPS = "configure_https"
ATTR_RESTART = "restart"

# 平台
PLATFORMS = ["sensor", "binary_sensor", "button", "switch"]
