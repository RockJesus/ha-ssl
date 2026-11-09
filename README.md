# HA SSL（Home Assistant 自定义集成）

在 Home Assistant 内部完成 **Let's Encrypt 证书签发与自动续期**，用阿里云 DNS 做 dns-01 验证。
不依赖 HA 官方 Let's Encrypt 加载项，也不依赖宿主机 DNS 解析器（DNS 记录通过阿里云 API 写入，生效检查走公共 DoH 解析器）。

## 解决什么问题

官方 Let's Encrypt 加载项在国内常见两类失败：

- 镜像来自 `ghcr.io`，加载项装不上；
- 加载项内部用 lego，写 TXT 前要先查 `_acme-challenge.<域名>` 的 SOA 来定位 zone，宿主机 DNS 被路由器/运营商劫持时会返回 `SERVFAIL`，报
  `could not find zone ... code=SERVFAIL`。

本集成用阿里云 OpenAPI 直接定位主域名并写入 TXT（`DescribeDomainRecords` / `AddDomainRecord`），绕开上述两步；协议实现只用到 `aiohttp` 与 `cryptography`（HA 自带），无需额外安装依赖。

## 功能

- 阿里云 DNS dns-01 签发，单域名证书
- 自动续期：默认证书剩余 ≤30 天时自动重签，可配置
- 续期成功后可自动重启 HA 以加载新证书（HA 只在启动时读取证书）
- 实体：证书到期时间、剩余天数、证书异常（problem）、立即签发按钮、自动续期开关
- 服务：`acme_cert.renew`（手动签发）、`acme_cert.configure_https`（写入 `configuration.yaml` 并重启，自动备份）
- 支持 Let's Encrypt 测试环境（staging），便于先验证流程

## 安装

HACS → 集成 → 右上角三个点 → 自定义存储库 → 添加 `https://github.com/RockJesus/ha-ssl`（类别选 Integration）→ 安装 → 重启 HA。

或手动放到 `config/custom_components/acme_cert/` 后重启。

## 配置

设置 → 设备与服务 → 添加集成 → **HA SSL**：

| 字段 | 说明 |
|---|---|
| 域名 | 需要签发证书的完整域名，如 `home.example.com` |
| 联系邮箱 | Let's Encrypt 到期通知邮箱 |
| AccessKey ID / Secret | 阿里云子账号，至少具备 `AliyunDNSFullAccess`（或该域名的解析读写权限） |
| 证书输出目录 | 默认 `/ssl`，也可是 `/config/ssl` |
| 测试环境 | 先用 staging 验证，确认无误后删除重建走生产 |

保存时会调用阿里云 API 校验凭据与该域名所属主域名，失败会提示 `invalid_auth`。

## 启用 HTTPS

方式 A（手动两行，最稳）：

```yaml
http:
  ssl_certificate: /ssl/fullchain.pem
  ssl_key: /ssl/privkey.pem
```

方式 B（用服务自动写入并重启）：

```yaml
service: acme_cert.configure_https
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
- 阿里云 AccessKey 保存在 HA 的配置条目中（`.storage`），建议使用最小权限子账号并定期轮换。

## 版本

- v1.0.2：仓库与项目整体更名为 ha-ssl（domain 仍为 `acme_cert`，实体不变）
- v1.0.1：集成显示名改为 HA SSL（domain 仍为 `acme_cert`，实体不变）
- v1.0.0：首个版本，支持阿里云 dns-01 签发、自动续期、到期实体与 HTTPS 配置服务。

## 许可

MIT
