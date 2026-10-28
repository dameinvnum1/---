# 词境 · 国内服务器部署

这个目录让词境脱离 Cloudflare 运行：Node 原生 HTTP + SQLite，复用同一份 `worker/src/index.js`，不需要重新实现业务逻辑。

> workers.dev 在国内会被 SNI 拦截，所以必须用自己的域名；境内服务器对外提供网站服务还需要 ICP 备案。

## 前置条件

- 一台境内云服务器（阿里云 / 腾讯云 / 华为云均可），Ubuntu 22.04 或 24.04
- 一个已完成 **ICP 备案** 的域名，解析到这台服务器
- Node.js **22.9+**（需要 `node:sqlite` 与 `--env-file-if-exists`）
- DeepSeek API Key

## 本地试跑

```bash
cd server
cp .env.example .env      # 填 AI_API_KEY
npm start                 # http://127.0.0.1:8788
```

首次启动会自动读取 `worker/schema.sql` 建表，数据库落在 `server/data/cijing.db`。

## 服务器部署

### 1. 装环境

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
node -v   # 需要 >= 22.9
```

### 2. 放代码

```bash
sudo mkdir -p /srv/cijing && sudo chown $USER /srv/cijing
git clone <你的仓库地址> /srv/cijing
cd /srv/cijing/server
cp .env.example .env
vim .env       # AI_API_KEY、ALLOWED_ORIGIN=https://你的域名、ADMIN_IDS=你的 user id
```

`ADMIN_IDS` 只需要填一次：首次启动后进后台「设置」页维护，之后以数据库为准。

### 3. systemd

`/etc/systemd/system/cijing.service`：

```ini
[Unit]
Description=Cijing
After=network.target

[Service]
Type=simple
WorkingDirectory=/srv/cijing/server
ExecStart=/usr/bin/node --env-file-if-exists=.env index.js
Restart=always
RestartSec=3
User=www-data
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

```bash
sudo chown -R www-data /srv/cijing/server/data
sudo systemctl daemon-reload
sudo systemctl enable --now cijing
sudo systemctl status cijing
```

### 4. nginx + 证书

`/etc/nginx/sites-available/cijing`：

```nginx
server {
    listen 80;
    server_name cijing.example.com;

    client_max_body_size 2m;

    location / {
        proxy_pass http://127.0.0.1:8788;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 180s;   # 生成接口最长可能跑两分钟
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/cijing /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d cijing.example.com
```

### 5. 验证

```bash
curl https://你的域名/api/config
curl -I https://你的域名/
```

浏览器打开域名，用 `ADMIN_IDS` 对应的账号登录后进 `/admin.html`。

## 备份

只有一个文件：`server/data/cijing.db`（WAL 模式下还有 `-wal` / `-shm`）。

```bash
sqlite3 /srv/cijing/server/data/cijing.db ".backup '/backup/cijing-$(date +%F).db'"
```

建议 cron 每天跑一次，保留最近 14 天。

## 和 Cloudflare 版本的差异

| 项目 | Cloudflare | 国内服务器 |
|---|---|---|
| 运行时 | Worker（V8 isolate） | Node.js |
| 数据库 | D1 | SQLite（`node:sqlite`） |
| 静态文件 | GitHub Pages | 同一个 Node 进程 |
| 成本 | 免费额度内基本为零 | 服务器 + 域名 + 备案 |
| 国内访问 | workers.dev 被拦 | 直连，延迟取决于机房 |

业务逻辑完全共用，`worker/src/index.js` 的改动两边同时生效；差别只在 `env.cijing_db` 的适配层（`server/db.js`）。

## 注意

- `ALLOWED_ORIGIN` 不要留 `*`，填自己的域名。
- `.env` 与 `data/` 已在 `.gitignore` 里，不会进仓库。
- 备案是域名与服务器层面的要求，代码无法绕过。
