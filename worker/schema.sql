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
  style_profile_id TEXT,               -- 参考文风卡；老库需手动 ALTER 补这一列
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_works_feed  ON works(visibility, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_works_genre ON works(visibility, genre, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_works_user  ON works(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- 点赞：用户 × 作品 联合主键，天然防重复
CREATE TABLE IF NOT EXISTS likes (
  user_id TEXT NOT NULL,
  work_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, work_id)
);
CREATE INDEX IF NOT EXISTS idx_likes_work ON likes(work_id);

-- 收藏：同上
CREATE TABLE IF NOT EXISTS favorites (
  user_id TEXT NOT NULL,
  work_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, work_id)
);
CREATE INDEX IF NOT EXISTS idx_favorites_work ON favorites(work_id);

-- 评论：status 预留给审核（visible | hidden）
CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  work_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  content TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'visible',
  created_at INTEGER NOT NULL,
  FOREIGN KEY (work_id) REFERENCES works(id)
);
CREATE INDEX IF NOT EXISTS idx_comments_work ON comments(work_id, created_at DESC);

-- 关注关系：follower 关注 followee
CREATE TABLE IF NOT EXISTS follows (
  follower_id TEXT NOT NULL,
  followee_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (follower_id, followee_id)
);
CREATE INDEX IF NOT EXISTS idx_follows_followee ON follows(followee_id);

-- 消息通知：点赞 / 收藏 / 评论 / 关注
-- dedupe_key 保证「取消后重新点赞」不会刷出一堆重复消息
CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,               -- 接收者
  actor_id TEXT NOT NULL,              -- 触发者
  type TEXT NOT NULL,                  -- like | favorite | comment | follow
  work_id TEXT,
  comment_id TEXT,
  excerpt TEXT,                        -- 评论摘要
  dedupe_key TEXT NOT NULL,
  read_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_dedupe ON notifications(dedupe_key);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at DESC);

-- 风格卡：从用户提供的参考文本里抽取出来的文风特征。
-- 原始文本分析完即丢弃，这里只存派生结果（含 3-5 句逐字短摘句作为锚点）。
-- rights 记录用户声明的权利来源，决定用它的作品能不能公开。
CREATE TABLE IF NOT EXISTS style_profiles (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  profile TEXT NOT NULL,               -- JSON：前面列出的各维度特征 + anchors
  rights TEXT NOT NULL,                -- own | licensed | public
  source_chars INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_style_profiles_user ON style_profiles(user_id, created_at DESC);

