# IPQ

IPQ 是一个部署在 Cloudflare Workers 上的 IP 查询页面。

## IP 纯洁度检测

查询时同时展示多个来源的 VPN、代理、Tor、机房和垃圾滥用标记、威胁情报报告及原始风险分，保留来源分歧。接口不可用或未返回的字段显示未知，机房标记不等于恶意。

页面支持手机与桌面布局，明暗主题跟随系统设置；检测来源、情报报告和评分依据可展开查看。

| 来源 | 检测内容 | 配置 |
| --- | --- | --- |
| [IPQuery](https://ipquery.io/docs) | VPN、代理、Tor、机房及来源风险分 | 无需密钥 |
| [Blackbox](https://blackbox.ipinfo.app/) | 网络类型、匿名网络标记、分类依据 | Beta 阶段无需密钥，服务规则可能变化 |
| [StopForumSpam](https://www.stopforumspam.com/usage) | 论坛垃圾滥用记录、记录次数和最近出现时间 | 无需密钥 |
| [AlienVault OTX](https://otx.alienvault.com/) | 威胁情报报告数、报告名称及白名单 / 误报标记 | 公开查询接口，受上游可用性限制 |
| [ipapi.is](https://ipapi.is/developers.html) | VPN、代理、Tor、机房及滥用标记 | 可选，配置 `IPAPI_IS_KEY` |

ipapi.is 的匿名接口已不提供上述风险字段。需要此来源时，注册其免费账号取得密钥，在 Cloudflare Workers 中添加 `IPAPI_IS_KEY` Secret；本地开发放在 `.dev.vars` 中。未配置时，其余四个来源正常工作。免费账号额度以[官方说明](https://ipapi.is/free-tier.html)为准；密钥只在 Worker 服务端使用。

参考评分从 92 分起扣，只计算已接入来源的检测项，详见[评分说明](docs/purity-scoring.md)。OTX 报告提及与欺诈 / 风险分逐项展示扣分和依据。必要数据不完整时不出总分，未知不算零风险。

每个接口最多等待 10 秒。Cloudflare Cache API 按来源和 IP 缓存成功结果 30 分钟、失败结果 1 分钟，页面标明查询时间与缓存状态。`/api/inspect` 保留原有字段，新增 `purity`，包含目标 IP、信号汇总和逐源结果。输入必须是有效的 IPv4 或 IPv6 地址。

来源选型参考 [egress-observatory](https://github.com/BlackSlience-Reaper/egress-observatory) 的公开数据源清单，接入逻辑按各服务公开接口独立实现。

项目地址：

- GitHub：https://github.com/noway1467/ipq
- Cloudflare Workers 文档：https://developers.cloudflare.com/workers/
- Cloudflare Git 集成文档：https://developers.cloudflare.com/workers/ci-cd/builds/

## 部署

1. Fork 此项目到你自己的 GitHub。
2. 打开 Cloudflare Workers。
3. 选择 `Workers & Pages` -> `Create` -> `Import a repository`。
4. 连接你的 GitHub 账号并选择你 fork 的仓库。
5. Cloudflare 识别到这是 Workers 项目后，直接部署即可。

## 当前项目配置

- Worker 名称：`ipq-worker`
- 入口文件：`src/worker.js`
- 配置文件：`wrangler.toml`
- 环境变量：`IPINFO_TOKEN`，用于展示 IPinfo Lite 检测结果。
- `wrangler.toml` 已内置示例变量：

```toml
[vars]
IPINFO_TOKEN = "example_ipinfo_token"
```

部署前请把示例值替换为你的 IPinfo API Token，或者使用 Wrangler Secret 保存真实 Token。后续更新 `wrangler.toml` 时请保留 `[vars]` 下的 `IPINFO_TOKEN` 配置。

IPinfo Lite 会展示以下字段：

- `ip`
- `network`
- `asn`
- `as_name`
- `as_domain`
- `as_type`，如果接口返回该字段会展示为 `AS Type`
- `country_code`
- `country`
- `continent_code`
- `continent`
- `anycast`
- `bogon`

DB-IP 会尽可能展示以下字段。Free API 通常包含 IP、洲、国家、省州、城市；如果 API 返回更高套餐字段，页面也会自动展示：

- `ipAddress`
- `continentCode`
- `continentName`
- `countryCode`
- `countryName`
- `isEuMember`
- `currencyCode`
- `currencyName`
- `phonePrefix`
- `languages`
- `stateProvCode`
- `stateProv`
- `district`
- `city`
- `geonameId`
- `zipCode`
- `latitude`
- `longitude`
- `gmtOffset`
- `timeZone`
- `weatherCode`
- `isp`
- `organization`
- `asn`
- `connectionType`
- `threatLevel`

## 本地开发部署

## 安装 Wrangler

# 方式1：npm（推荐）
npm install -g wrangler

# 方式2：yarn
yarn global add wrangler

# 验证安装
wrangler --version

## 登录cloudfalre
- wrangler login

## 初始化项目
wrangler init my-worker

## 本地开发
- wrangler dev

如需本地测试 IPinfo 结果，在项目根目录创建 `.dev.vars`：

```ini
IPINFO_TOKEN=你的_ipinfo_token
```

## 部署到cloudfalre
- wrangler deploy

部署后在 Cloudflare Workers 的环境变量中添加 `IPINFO_TOKEN`。也可以使用 Wrangler Secret：

```bash
wrangler secret put IPINFO_TOKEN
```

如果使用 Wrangler Secret，`wrangler.toml` 中的示例值只作为占位说明，真实 Token 不会写入仓库。
