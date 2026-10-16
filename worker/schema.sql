-- 词境 D1 schema
-- 用 wrangler d1 execute cijing-db --remote --file=./schema.sql 执行

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,          -- 小写归一化
  name TEXT NOT NULL,
  password_hash TEXT,                  -- 纯验证码用户可为空
  password_salt TEXT,
  plan TEXT NOT NULL DEFAULT 'trial',  -- trial | pro（付费预留）
  quota_total INTEGER NOT NULL DEFAULT 5,
  quota_used INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS invite_codes (
  code TEXT PRIMARY KEY,
  plan TEXT NOT NULL DEFAULT 'trial',  -- 决定注册后拿到的 plan
  quota INTEGER NOT NULL DEFAULT 5,
  max_uses INTEGER NOT NULL DEFAULT 1,
  used_count INTEGER NOT NULL DEFAULT 0,
  note TEXT,                           -- 发给谁、何时发（人工发码对账用）
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS otp_codes (  -- 注册与登录共用
  email TEXT NOT NULL,
  purpose TEXT NOT NULL,               -- register | login
  code_hash TEXT NOT NULL,             -- 只存哈希，不存明文
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  sent_at INTEGER NOT NULL,
  PRIMARY KEY (email, purpose)
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS works (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  genre TEXT NOT NULL,
  subgenre TEXT NOT NULL,
  tropes TEXT,                         -- JSON 数组字符串
  hook TEXT,
  summary TEXT,
  content TEXT NOT NULL,               -- 段落用空行分隔
  words TEXT NOT NULL,                 -- JSON 数组
  vocab TEXT NOT NULL,                 -- JSON 对象
  visibility TEXT NOT NULL DEFAULT 'private',
  published_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_works_feed  ON works(visibility, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_works_genre ON works(visibility, genre, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_works_user  ON works(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
