// 国内服务器版本：用 Node 原生 HTTP 跑同一份 Worker 逻辑。
// 同一个端口同时提供 /api/* 与静态文件，前面挂 nginx 做 TLS 即可。
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { D1Database, openDatabase } from "./db.js";
import worker from "../worker/src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..");
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, "cijing.db");
const PORT = Number(process.env.PORT) || 8788;
const HOST = process.env.HOST || "127.0.0.1";

fs.mkdirSync(DATA_DIR, { recursive: true });
const sqlite = openDatabase({ path: DB_PATH, schemaPath: path.join(ROOT, "worker/schema.sql") });

const env = {
  cijing_db: new D1Database(sqlite),
  AI_API_KEY: process.env.AI_API_KEY || "",
  AI_BASE_URL: process.env.AI_BASE_URL || "https://api.deepseek.com",
  AI_MODEL: process.env.AI_MODEL || "deepseek-chat",
  ALLOWED_ORIGIN: process.env.ALLOWED_ORIGIN || "*",
  EMAIL_OTP_ENABLED: process.env.EMAIL_OTP_ENABLED || "false",
  ADMIN_IDS: process.env.ADMIN_IDS || "",
  STYLE_WHITELIST: process.env.STYLE_WHITELIST || "",
};

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};

// 只透传前端真正会用到的头，避免把 hop-by-hop 头塞进 Request
const FORWARD_HEADERS = [
  "content-type",
  "authorization",
  "cookie",
  "origin",
  "user-agent",
  "accept",
  "accept-language",
  "referer",
];

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(chunks.length ? Buffer.concat(chunks) : undefined));
    req.on("error", reject);
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);

  // ---- API：交给 Worker 里同一份 fetch handler ----
  if (url.pathname.startsWith("/api/")) {
    const headers = {};
    for (const name of FORWARD_HEADERS) {
      const value = req.headers[name];
      if (value) headers[name] = Array.isArray(value) ? value.join(", ") : value;
    }
    // 限流与审计都靠这个头识别来源；前面有 nginx 时优先取 X-Forwarded-For
    headers["cf-connecting-ip"] = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "")
      .split(",")[0]
      .trim();

    const body = await readBody(req);
    let request;
    try {
      request = new Request(url, {
        method: req.method,
        headers,
        body: body && req.method !== "GET" && req.method !== "HEAD" ? body : undefined,
      });
    } catch (error) {
      sendJson(res, 400, { error: "请求格式不正确" });
      return;
    }

    try {
      const response = await worker.fetch(request, env);
      const payload = Buffer.from(await response.arrayBuffer());
      const responseHeaders = {};
      response.headers.forEach((value, name) => {
        responseHeaders[name] = value;
      });
      res.writeHead(response.status, responseHeaders);
      res.end(payload);
    } catch (error) {
      console.error("[api] 未捕获异常:", error);
      sendJson(res, 500, { error: "服务器错误" });
    }
    return;
  }

  // ---- 同源部署：让前端把请求打回自己 ----
  if (url.pathname === "/ai-config.js") {
    res.writeHead(200, { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-cache" });
    res.end("window.CIJING_API_BASE = window.location.origin;");
    return;
  }

  // ---- 静态文件 ----
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === "/") pathname = "/index.html";
  const file = path.resolve(ROOT + pathname);
  if (!file.startsWith(path.resolve(ROOT)) || file.includes(path.sep + "worker" + path.sep) || file.includes(path.sep + "server" + path.sep)) {
    res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Forbidden");
    return;
  }
  fs.readFile(file, (error, data) => {
    if (error) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }
    res.writeHead(200, {
      "Content-Type": MIME[path.extname(file)] || "application/octet-stream",
      "Cache-Control": pathname.endsWith(".html") ? "no-cache" : "public, max-age=3600",
    });
    res.end(data);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`词境服务已启动：http://${HOST}:${PORT}`);
  console.log(`数据库：${DB_PATH}`);
});
