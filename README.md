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

## 部署到cloudfalre
- wrangler deploy
