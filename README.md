# IPQ

IPQ 是一个部署在 Cloudflare Workers 上的 IP 查询页面。

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
