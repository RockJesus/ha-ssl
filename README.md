# HA SSL

[![Hassfest](https://github.com/RockJesus/ha-ssl/actions/workflows/hassfest.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/hassfest.yml)
[![HACS Action](https://github.com/RockJesus/ha-ssl/actions/workflows/hacs.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/hacs.yml)
[![ACME Self Test](https://github.com/RockJesus/ha-ssl/actions/workflows/selftest.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/selftest.yml)
[![Privacy Scan](https://github.com/RockJesus/ha-ssl/actions/workflows/privacy.yml/badge.svg)](https://github.com/RockJesus/ha-ssl/actions/workflows/privacy.yml)

在 Home Assistant 内部完成 **Let's Encrypt 证书签发、HTTPS 自动启用与自动续期**，
并把 **动态域名（DDNS）** 一起接管——原来交给 Lucky 或路由器的那件事也不用再单独跑了。
只要选一个 DNS 服务商、填它的凭据，其余全自动——不需要加载项，也不需要宿主机能解析 DNS。

> 适合国内环境：官方 Let's Encrypt 加载项常因镜像拉不到而装不上，或卡在 `code=SERVFAIL`——
> 那个加载项靠宿主机 DNS 查 `_acme-challenge.<域名>` 的 SOA 来定位 zone，DNS 被路由器或运营商劫持时查不到。
> 本集成直接用服务商 API 定位 zone 并写 TXT 记录，全程绕开宿主机 DNS。

## 快速开始

1. **装集成**：HACS 添加自定义仓库 `https://github.com/RockJesus/ha-ssl`（类别选 Integration），或把 `custom_components/ha_ssl/` 放进 `config/`，然后重启。
2. **添加集成**：设置 → 设备与服务 → 添加集成 → **HA SSL** → 选 DNS 服务商 → 填凭据。
3. **等它做完**：签发证书 → 写入 HTTPS 配置 → 发通知让你自己重启（集成从不自动重启）→ 之后每 6 小时巡检、到期前自动续签。

完成后改用 `https://<域名>:8123` 访问，手机 App 里的服务器地址也要同步改成 https。

## 只填服务商凭据

| 服务商 | 需要填 | 最小权限 |
|---|---|---|
| 阿里云云解析 | AccessKey ID + Secret | RAM 子账号授予 `AliyunDNSFullAccess`，或只给该域名的解析读写 |
| 腾讯云 DNSPod | Token ID + Token | 账号设置 → API 密钥创建，需能管理该域名 |
| Cloudflare | API Token | `Edit zone DNS` 模板，Zone 限定到该域名 |

域名默认取 HA 自己的 `external_url`/`internal_url`，留空即可；没有邮箱字段（ACME 账号本来就不要求联系人）。
凭据只用于调用服务商接口，保存在 HA 本地配置（`.storage`），建议用最小权限子账号并定期轮换。

## 自动完成的事

| 阶段 | 行为 |
|---|---|
| 签发 | dns-01 验证，自动写入再删除 `_acme-challenge` TXT 记录 |
| 启用 HTTPS | 写进当前 HA 版本真正读取的 HTTP 配置（2026.11+ 是 `.storage/http`；没有该存储的旧版只发通知，给出要手动加进 `configuration.yaml` 的两行，集成不改写用户 YAML） |
| 确认 | 重启后探测本机 TLS，通了就固化配置（避免 5 分钟自动回退），并把 `external_url` 切成 `https://` |
| 续期 | 每 6 小时检查一次，剩余 ≤30 天自动重签；成功后发持久通知，由你决定何时重启加载新证书 |

签发、启用与续期各发一条持久通知，说明正在做什么、改了哪些 HTTPS 设置（证书路径、私钥、端口、TLS 档位）、重启后该用哪个地址访问。集成内没有任何自动重启调用。

## 动态域名（可选）

家宽公网 IP 会变时，打开它就够了，不必再装 Lucky 之类的 DDNS 工具：

首次配置时，凭据校验通过后就会多出一步「动态 DNS（可选）」：打开开关，填要维护的记录、记录类型、检查间隔和 TTL 即可，不用等配置完再进选项。之后想改，随时进 **选项** 打开「启用动态域名解析」，在**记录清单**里每行写一条 `名称 | 类型 | 值`。默认每 5 分钟查一次公网地址，和记录比对，变了才改；记录不存在时自动创建。

```text
dyc.example.com  | A     | auto
dyc.example.com  | AAAA  | auto
home.example.com | CNAME | other.example.com
example.com      | TXT   | v=spf1 -all
```

| 字段 | 说明 |
|---|---|
| 名称 | 完整域名；也可以写短标签（如 `home`），会自动挂到主记录所在 zone |
| 类型 | `A`、`AAAA`、`CNAME`、`TXT`，可任意条数、不同类型混用 |
| 值 | `A`/`AAAA` 填 `auto` 表示跟随本机公网地址，也可填固定地址；`CNAME` 填目标主机名；`TXT` 填内容 |

- 走的是同一套服务商凭据，不额外配置；阿里云、DNSPod、Cloudflare 都支持这四类记录。
- **A**：查公网 IPv4 并写 A 记录；检测到运营商级 NAT（`100.64/10`）会直接报错，因为那种情况改 DNS 也没用。
- **AAAA**：查公网 IPv6（自动剔除回环、链路本地、ULA 等不可路由地址）；本机没有 IPv6 出网时只报该项失败，不影响 A 记录。
- **CNAME**：别名指向你指定的主机名；DNS 不允许同名 CNAME 与 A/AAAA 并存，清单里会拦下并提示。
- 每类、每条记录独立对账，任一条失败不会拖垮其他条；失败原因汇总在 `last_error`。
- TTL 可调（默认 600 秒）；地址变化或更新失败会发持久通知，同时触发 `ha_ssl_ddns_changed` 事件，可接自动化。
- 实体「公网 IP」「公网 IPv6」「维护的记录数」显示当前状态；属性里有逐条记录结果、双栈检测、最近 5 次变更。
- 想立刻验证：调用 `ha_ssl.update_ddns`，返回逐条结果、双栈状态与变更历史。

## 证书增强

| 选项 / 服务 | 说明 |
|---|---|
| 证书域名清单 | 逗号分隔多个域名，支持 `*.example.com` 泛域名（DNS-01 可签），一张证书覆盖全部 |
| 到期提醒阈值 | 剩余天数低于该值时发持久通知，每天最多一次；可配 Webhook 同步推到企业微信/飞书 |
| HTTPS 端口 / TLS 档位 | 写 HTTPS 配置时一并带入；只在 HA 的 HTTP 配置存储里已有对应键时才生效 |
| `ha_ssl.diagnose` | 一次性体检：IPv4/IPv6 出网、公网地址、zone 定位、证书链与私钥匹配 |
| `ha_ssl.verify_cert` | 校验磁盘上的证书：私钥是否匹配、链是否完整、SAN 覆盖哪些域名、剩余天数 |
| `ha_ssl.backup_cert` | 把证书与私钥打包成 zip，换机/重装时直接恢复，省一次签发 |
| `ha_ssl.purge` | 危险操作：移除 HTTP 配置里的证书、删除证书 / 账户密钥 / 备份，需显式 `confirm: true` |
| `ha_ssl.restore_cert` | 从 zip 恢复证书对，先校验匹配再覆盖 |

## 实体与服务

| 类型 | 实体 |
|---|---|
| 传感器 | 证书到期时间、剩余天数、公网 IP、公网 IPv6、维护的记录数 |
| 二进制传感器 | 证书异常 |
| 按钮 | 立即签发、同步 HTTP 设置（把证书与端口写入 HA 的 HTTP 配置，成功后提示重启） |
| 开关 | 自动续期 |

| 服务 | 用途 |
|---|---|
| `ha_ssl.renew` | 立刻签发/续期一次 |
| `ha_ssl.update_ddns` | 立刻比对公网地址并按记录清单改写 A / AAAA / CNAME / TXT |
| `ha_ssl.configure_https` | 写入 HTTPS 配置并通知重启（管理员服务） |
| `ha_ssl.promote_https` | 固化待生效的 HTTPS 配置，取消自动回退（管理员服务） |
| `ha_ssl.probe` | 诊断：候选 ACME 目录连通性、本机 http/https 自检、HTTP 配置存储（管理员服务） |
| `ha_ssl.diagnose` | 网络与证书一体化诊断（管理员服务） |
| `ha_ssl.verify_cert` | 证书链/私钥/到期自检 |
| `ha_ssl.backup_cert` / `ha_ssl.restore_cert` | 证书备份与恢复；只接受允许范围内的路径，并拒绝 `www` 目录（`/local/` 无需认证即可下载）|
| `ha_ssl.purge` | 清理证书、账户密钥、备份并从 HTTP 配置移除证书（需 `confirm: true`，管理员服务）|

## 注意

- 一张证书可覆盖多个域名或泛域名，但所有域名都必须由同一个 DNS 服务商托管（签发时只用一个凭据）。
- 8123 上 TLS 后明文 `http://` 立刻失效。家里 Wi-Fi 用域名访问需要路由器支持 NAT 回环；不支持就在内网用 `https://<IP>:8123` 并单独处理信任。
- 证书目录默认 `/config/ssl`，**不是** `/ssl`——后者是加载项的挂载路径，HA 本体里没有。
- 选项里可调提前续期天数（7–89），也可关掉自动续期。新证书一律等你自己重启后才生效。
- 会改 HTTP 配置、读写私钥或删文件的服务（`configure_https`、`promote_https`、`probe`、`diagnose`、`backup_cert`、`restore_cert`、`purge`）注册为管理员服务，非管理员账号调用会被拒绝。

## 开发与发布

| 工作流 | 作用 |
|---|---|
| Hassfest | 官方集成校验：manifest 字段与键序、文件结构、翻译、services |
| HACS Action | HACS 发布物校验：仓库结构、`hacs.json`、集成元数据 |
| ACME Self Test | 假 ACME 服务器跑通「下单 → authz → dns-01 → finalize → 下载证书」，并检查包内跨模块导入 |
| Privacy Scan | 脱敏扫描：工作区 + **完整 git 历史**一起查，命中即红 |

本地可跑：

```bash
python3 scripts/check_privacy.py            # 只查工作区
python3 scripts/check_privacy.py --history  # 连 git 历史一起查
python3 scripts/import_check.py             # 包内导入一致性
```

脱敏检查项：邮箱、公网 IP、JWT、云厂商 AccessKey、手机号、VIN、以及白名单外的域名；输出打码（Actions 日志本身也是公开的）。
文档统一用 `example.com` 这类占位域名。历史若发现残留，用 `git filter-repo --replace-text` 重写后 force push。

发布纪律：`manifest.json` 的 `version` 与 tag 同步、按十进制逐位递增（段内不进两位数）、tag 指向最新 main、Release 不放 zip asset、全文件 UTF-8 无 BOM。变更记录只写在 GitHub Releases，README 只保留使用说明。

## 许可

MIT
