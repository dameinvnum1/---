# 词境 Cijing

用每天背的英语单词，写一篇能读下去的中文短篇小说。

词境把「背单词」这件事从记忆卡片里拽出来，放回叙事里：你上传背词 App 的截图，系统识别出当天要记的词，再让你选题材、剧情梗和可选的参考文风，生成一篇第一人称短篇——每个目标词都必须真实地出现在正文里，读完还能点开词卡核对语境义。

- 在线体验：<https://dameinvnum1.github.io/---/>
- 管理后台：`/admin.html`（仅白名单账号可进）

## 功能

**创作**

- 截图 OCR 识别词单（浏览器本地识别，图片不上传）
- 结构化设定：大类 / 细分题材 / 1-3 个剧情梗 / 自由剧情设定
- 词汇硬性覆盖检查：少一个词就自动重试，最多 3 次
- 参考文风：上传或粘贴一段有权使用的文本，抽取成可复用的「风格卡」，生成时按它的语感写；原文分析后即丢弃，只保留派生特征
- 目标词用法边界检测：把英文词当人名、当「被讨论的对象」这类硬塞写法会被识别并重写
- 生成失败自动退还额度

**社区**

- 推荐流（互动加权 + 时间衰减）、新作、分类与细分题材筛选
- 作品详情、全文阅读、词卡释义
- 点赞、收藏、评论（支持一层楼中楼）、关注、消息通知
- 公开作者主页：作品、关注、粉丝

**账号与管理**

- 邮箱 + 密码注册（邀请码制）；可选邮箱验证码模式
- 内置 12 款图案头像
- 管理后台：概览与用量、用户、作品、评论、邀请码、审计日志、白名单维护

## 技术栈

| 层 | 选型 |
|---|---|
| 前端 | 单文件 `index.html` / `admin.html`，原生 JS + Tailwind CDN + Lucide |
| 后端 | Cloudflare Worker（单文件 `worker/src/index.js`），手写路由 |
| 数据库 | Cloudflare D1（SQLite 方言），`worker/schema.sql` |
| 模型 | DeepSeek `deepseek-chat`，服务端调用，key 只存在 Worker secret |
| 部署 | Worker + GitHub Pages；另附 Node 版本用于国内服务器 |

## 目录

```
index.html            读者端（单文件应用）
admin.html            管理后台
ai-config.js          前端读取的后端地址
worker/
  src/index.js        全部后端逻辑：鉴权、生成、社区、管理接口
  schema.sql          表结构（手工执行：wrangler d1 execute）
  wrangler.toml       Worker 配置与 D1 绑定
server/               国内服务器版本（Node + SQLite，复用同一份后端逻辑）
```

## 本地开发

```bash
# 后端
cd worker
npx wrangler d1 execute cijing-db --local --file=./schema.sql
npx wrangler dev --port 8788

# 前端：任选一个静态服务器，把 ai-config.js 指向 http://127.0.0.1:8788
```

本地需要 `worker/.dev.vars`（不提交）：

```
AI_API_KEY="sk-..."
OTP_DEV_MODE=true
```

## 部署

### Cloudflare

```bash
cd worker
npx wrangler d1 execute cijing-db --remote --file=./schema.sql
npx wrangler secret put AI_API_KEY
npx wrangler deploy
```

前端是纯静态文件，推到 GitHub 后由 Pages 托管。

> 白名单（参考文风 / 管理后台）不在仓库里，存在 D1 的 `settings` 表，通过后台「设置」页维护。

### 国内服务器

见 [`server/README.md`](server/README.md)。Node 版本复用了同一份 `worker/src/index.js`，用 `node:sqlite` 顶替 D1，nginx 反代 + 证书即可。

## 设计取舍

- **词汇覆盖是硬约束，其余让位于可读性**：先保证每个词都出现，再通过自动重试处理漏词、抄锚点、生硬塞词三类问题。
- **成本优先**：生成接口原子占额度、失败退还；按人限流；每次模型调用都记录 token 用量。
- **数据最小化**：截图不上传，参考文本不落库，管理后台只暴露运营必需的字段。
