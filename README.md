# HA SSL（Home Assistant 自定义集成）

[![Hassfest](https://github.com/RockJesus/ha-ssl/actions/workflows/hassfest.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/hassfest.yml)
[![HACS Action](https://github.com/RockJesus/ha-ssl/actions/workflows/hacs.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/hacs.yml)
[![Privacy Scan](https://github.com/RockJesus/ha-ssl/actions/workflows/privacy.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/privacy.yml)

在 Home Assistant 内部完成 **Let's Encrypt 证书签发与自动续期**，用阿里云 DNS 做 dns-01 验证。
不依赖 HA 官方 Let's Encrypt 加载项，也不依赖宿主机 DNS 解析器（DNS 记录通过阿里云 API 写入，生效检查走公共 DoH 解析器）。

## 解决什么问题

官方 Let's Encrypt 加载项在国内常见两类失败：

- 镜像来自 `ghcr.io`，加载项装不上；
- 加载项内部用 lego，写 TXT 前要先查 `_acme-challenge.<域名>` 的 SOA 来定位 zone，宿主机 DNS 被路由器/运营商劫持时会返回 `SERVFAIL`，报
  `could not find zone ... code=SERVFAIL`。

本集成用阿里云 OpenAPI 直接定位主域名并写入 TXT（`DescribeDomainRecords` / `AddDomainRecord`），绕开上述两步；协议实现只用到 `aiohttp` 与 `cryptography`（HA 自带），无需额外安装依赖。

## 功能

- dns-01 签发，单域名证书；DNS 服务商可选 **阿里云云解析 / 腾讯云 DNSPod / Cloudflare**
- 自动续期：默认证书剩余 ≤30 天时自动重签，可配置
- 续期成功后可自动重启 HA 以加载新证书（HA 只在启动时读取证书）
- 实体：证书到期时间、剩余天数、证书异常（problem）、立即签发按钮、自动续期开关
- 服务：`ha_ssl.renew`（手动签发）、`ha_ssl.configure_https`（写入 `configuration.yaml` 并重启，自动备份）
- 支持 Let's Encrypt 测试环境（staging），便于先验证流程

## 安装

HACS → 集成 → 右上角三个点 → 自定义存储库 → 添加 `https://github.com/RockJesus/ha-ssl`（类别选 Integration）→ 安装 → 重启 HA。

或手动放到 `config/custom_components/ha_ssl/` 后重启。

## 配置

设置 → 设备与服务 → 添加集成 → **HA SSL**，分两步：

**第 1 步：域名与服务商**

| 字段 | 说明 |
|---|---|
| DNS 服务商 | 阿里云云解析 / 腾讯云 DNSPod / Cloudflare |
| 域名 | 需要签发证书的完整域名，如 `home.example.com` |
| 证书输出目录 | 默认 `/ssl`，也可是 `/config/ssl` |
| 测试环境 | 先用 staging 验证，确认无误后删除重建走生产 |

**第 2 步：该服务商的凭据**

| 服务商 | 需要的字段 | 权限要求 |
|---|---|---|
| 阿里云云解析 | AccessKey ID + Secret | 子账号至少 `AliyunDNSFullAccess`，或该域名的解析读写 |
| 腾讯云 DNSPod | Token ID + Token | 控制台「密钥管理」生成的 API Token，需能管理该域名 |
| Cloudflare | API Token | 模板 Edit zone DNS（Zone.DNS 编辑权限） |

不需要填邮箱：ACME 账号本身不要求联系人，Let's Encrypt 的到期通知在证书自动续期的前提下也用不上。

保存时会调用对应服务商 API 校验凭据并确认域名归属，失败提示 `invalid_auth`（凭据无效或账号里没有该域名）、`cannot_connect`（网络不通）。

## 启用 HTTPS

方式 A（手动两行，最稳）：

```yaml
http:
  ssl_certificate: /ssl/fullchain.pem
  ssl_key: /ssl/privkey.pem
```

方式 B（用服务自动写入并重启）：

```yaml
service: ha_ssl.configure_https
data:
  restart: true
```

它会先备份 `configuration.yaml`，把两行插入已有 `http:` 段或追加新段，然后重启。写入后请先看日志确认无误。

## 续期机制

- 协调器每 6 小时读一次证书文件；
- 剩余天数 ≤ `renew_days`（默认 30）且开启自动续期时执行签发；
- 签发成功后如开启「续期后自动重启」则重启 HA；关闭时请自行在需要时重启，或配合 `cert_expiry` 监控。

## 注意

- 证书只对配置的单个域名有效，不支持泛域名。
- 8123 启用 TLS 后明文 `http://` 立即失效；家里 Wi-Fi 访问同一域名需要路由器支持 NAT 回环（hairpin），否则内网改用 IP + 例外配置。
- 服务商凭据保存在 HA 的配置条目中（`.storage`），建议使用最小权限的子账号 / API Token 并定期轮换。
- 三个服务商的 zone 定位都走服务商 API，不查宿主机 DNS，因此不受路由器或运营商 DNS 劫持影响。

## 开发与发布

仓库按 HA 官方自定义集成规范维护，CI 三项检查：

| 工作流 | 作用 |
|---|---|
| Hassfest | 官方集成校验：manifest 字段与键序、文件结构、翻译 key、services 定义 |
| HACS Action | HACS 发布物校验：仓库结构、`hacs.json`、集成元数据 |
| Privacy Scan | 自写脱敏扫描：工作区与**完整 git 历史**一起查，命中即红 |

发布物结构符合官方规范：`manifest.json` 键按字母序、`custom_components/ha_ssl/brand/` 提供亮/暗 8 个品牌图、`translations/` 中英齐全、`services.yaml` 与 `strings.json` 保持一致。

脱敏扫描本地也能跑：

```bash
python3 scripts/check_privacy.py            # 只查工作区
python3 scripts/check_privacy.py --history  # 连 git 历史一起查
```

检查项：邮箱、公网 IP、JWT、阿里云 AccessKey（`LTAI` 前缀）、手机号、VIN、以及不在白名单里的域名。
输出一律打码（公开仓库的 Actions 日志本身也是公开的），文档统一用 `example.com` 这类占位域名；
历史里发现残留用 `git filter-repo --replace-text` 重写，改完 force push。

发布纪律：`manifest.json` 的 `version` 与 tag 同步递增、tag 指向最新 main、Release 不放 zip asset（HACS 走归档模式）、全文件 UTF-8 无 BOM。

## 版本

- v1.0.7：支持多 DNS 服务商（阿里云云解析 / 腾讯云 DNSPod / Cloudflare），配置改为「先选服务商、再填凭据」两段式；去掉邮箱字段（ACME 账号不要求联系人）
- v1.0.6：补 manifest `categories`（`computers_network`）、iot_class 修正为 `cloud_polling`、品牌图补齐深色主题（icon/logo 各 2 种主题共 8 个文件）
- v1.0.5：补齐品牌图 `custom_components/ha_ssl/brand/`（icon/logo 各含 @2x），仓库补 topics，HACS Action 校验转绿
- v1.0.4：加入 Hassfest / HACS Action / Privacy Scan 三个 CI 工作流与脱敏脚本 `scripts/check_privacy.py`
- v1.0.3：集成代码目录与 domain 一并改为 `ha_ssl`（`custom_components/ha_ssl`），服务名变为 `ha_ssl.renew` / `ha_ssl.configure_https`，账户密钥目录改为 `/config/ha_ssl`
- v1.0.2：仓库与项目整体更名为 ha-ssl
- v1.0.1：集成显示名改为 HA SSL（domain 仍为 `acme_cert`，实体不变）
- v1.0.0：首个版本，支持阿里云 dns-01 签发、自动续期、到期实体与 HTTPS 配置服务。

## 许可

MIT
