# DDNS-RS

#### 介绍
轻量动态域名解析服务：检测本机或公网 IP 变化并自动同步到 DNS 服务商，单个二进制内置 Web 控制台。

#### 软件架构
- **双触发模式**：「监听」（本机地址变化事件即时触发：Linux/Android 走 netlink，Windows 走 `NotifyUnicastIpAddressChange`；平台不支持或事件源失效时自动降级为轮询并隐藏该选项）或「轮询」（10–86400 秒自定义间隔）；监听模式支持网口过滤（fnmatch 风格通配符，仅指定网口的地址变化才触发）。
- **多来源取址**：公网回显接口、本机网卡（支持 fnmatch 风格通配符）、自定义命令（超 20 秒自动终止）三类来源可混合多块按序回退，逐块取首命中；从回显文本抓取地址按地址族文法切词，支持 IPv6 内嵌 IPv4 写法与句读包裹，IPv4-mapped 地址归 IPv4 族不写入 AAAA。
- **多家服务商**：阿里云 DNS、阿里云 ESA、腾讯云（API 3.0）、DNSPod（旧 API）、华为云、百度云、火山引擎、Cloudflare、Porkbun、GoDaddy、Namecheap、Callback 自定义回调；`trait` 抽象。
- **Web 控制台**：卡片风格，任务增删改查、实时状态与日志、手动触发；简体中文 / 繁體中文 / English 三语切换。
- **单密码鉴权**：首次使用引导设置密码（仅接受本机/局域网来源，防公网抢占），Argon2id 散列 + HMAC 会话令牌 + 密码校验失败限速（同源连续失败 5 次锁定 5 分钟）；令牌默认 30 分钟滑动过期（`token_ttl` 可改），有操作自动续期、无操作到期自动退出。
- **可选禁止公网访问**：开启后仅本机与局域网来源可访问全部路由（含静态资源），不信任 `X-Forwarded-For` 等请求头。

#### 使用说明

```bash
./ddns-rs                          # 默认读取 ./config.json，监听 :::9999 与 0.0.0.0:9999（双栈）
./ddns-rs -c /etc/ddns.json        # 指定配置文件
./ddns-rs --reset-password 新密码  # 忘记密码时重置（至少 8 位）
```

#### 配置

`config.json` 示例：

```json
{
  "port": 9999,
  "not_allow_wan": false,
  "site_title": "DDNS-RS",
  "lang": "zh-cn",
  "log_cap": 50,
  "token_ttl": 1800,
  "entries": [
    {
      "name": "家庭宽带",
      "enabled": true,
      "mode": "listen",
      "interval": 300,
      "watch": ["eth*", "rndis*"],
      "zone": "example.com",
      "sub_domains": "home, vpn",
      "ttl": 0,
      "ipv4": { "enabled": true, "sources": [{ "type": "url", "url": ["https://ipv4.icanhazip.com"] }] },
      "ipv6": { "enabled": true, "sources": [{ "type": "netInterface", "name": ["eth0"] }, { "type": "url", "url": ["https://ipv6.icanhazip.com"] }] },
      "provider": { "type": "cloudflare", "token": "……", "proxied": false }
    }
  ]
}
```

| 字段 | 说明 |
| --- | --- |
| `port` | 监听端口（默认 `9999`），双栈绑定 `::` 与 `0.0.0.0`（Linux/Android 上 `::` 默认双栈单监听，Windows 上双监听并存，系统禁用 IPv6 时退化为仅 IPv4）；保存时探针验证可绑定后自动换轮重绑，前端待新端口可达再跳转，超时则提示手动访问 |
| `not_allow_wan` | 禁止公网访问（默认 `false`） |
| `pwd_hash` | 密码的 Argon2id 散列，留空表示尚未初始化 |
| `site_title` | 站点标题，至多 64 字符 |
| `lang` | 界面语言：`zh-cn`（默认）/ `zh-tw` / `en` |
| `log_cap` | 日志保留条数（默认 `50`，范围 50–2000） |
| `token_ttl` | 会话令牌有效期秒数（默认 `1800`，下限 60，不设上限），无操作自然到期 |
| `mode` | 触发模式：`listen`（新建任务默认）/ `poll`（配置文件缺省值） |
| `interval` | 轮询间隔秒数（10–86400，默认 300），无事件源平台的监听任务按此降级轮询 |
| `watch` | 监听模式的网口过滤，字符串数组，支持 `*` `?` `[...]` 通配符；空数组监听全部网口 |
| `zone` | 根域名，粘贴完整域名按 Public Suffix List 自动拆分子域，IDN 调用服务商前自动转 punycode |
| `sub_domains` | 子域名，逗号/空白分隔；留空或 `@` 表示根域名 |
| `ttl` | 记录 TTL 秒数，`0` 表示服务商默认值 |
| `ipv4` / `ipv6` | 地址族开关与取址来源，至少启用其一（Namecheap 仅支持 IPv4）；启用的地址族必须显式填写 `sources`，缺省留空会被拦截 |

取址来源（`sources`）：有序块列表，逐块按序回退——前一来源取不到地址自动尝试下一块，全失败才判定「未获取到地址」，快来源靠前可缩短最坏耗时。每块为一种取址方式（`type`）：`url`（公网回显接口数组，块内多候选按序回退，每项为完整 URL）、`netInterface`（网卡名数组，块内按序回退——前一无对应族地址取下一个，每项为完整网口名，可含空格/逗号（如 Windows「以太网 2」），支持 `*` `?` `[...]` 通配，可填暂不存在的网口）、`cmd`（自定义命令）。同类型可重复成块（如两个不同命令）。前端来源区为白卡多行（旧版 iOS 列表风格，非嵌套卡片），各来源以横线分隔；每来源一行「来源 N」标签 + 类型 seg（网卡/命令/接口一键即时切换，按类型保留值）+ `↑` `↓` `×`，`↑` `↓` 调整块序、`×` 删除（来源 1 不可删除），下方为该来源值区；单来源时标签显示「来源」（无序号、无操作按钮）；底部横线下「+ 添加来源 N」一键追加新块（N 为下一个来源序号，随块数动态显示；默认留空，内置接口与网口候选走建议列表一键补全）；值区为编号 chips 行：每项可点击原地编辑（一项即一个完整值）、`↑` `↓` 调整顺序、`×` 删除，底部输入行回车/点击建议即追加并去重，输入时按当前内容过滤弹出建议供快速选择，序号即回退优先级。新建任务默认网卡块预填首个网口。

| 服务商 | 参数 | 备注 |
| --- | --- | --- |
| `aliyun` | `access_key_id`、`access_key_secret` | |
| `aliesa` | `access_key_id`、`access_key_secret` | IP 记录为合并型 `A/AAAA`，双栈更新自动合并保留对族 |
| `tencent` | `secret_id`、`secret_key` | 腾讯云 DNSPod API 3.0 密钥 |
| `dnspod` | `id`、`token` | 旧 API 的 Token 对，固定管理「默认」线路 |
| `huawei` | `access_key_id`、`secret_key` | |
| `baidu` | `access_key_id`、`secret_key` | |
| `volcengine` | `access_key_id`、`secret_key` | |
| `porkbun` | `apikey`、`secretapikey` | 根域名子域以空串表示 |
| `godaddy` | `key`、`secret` | PUT 直接替换该主机名下同类型全部记录 |
| `namecheap` | `password` | 动态 DNS 密码，仅 IPv4 |
| `cloudflare` | `token`、`proxied` | Zone ID 带缓存，凭据不变期间不重复查询 |
