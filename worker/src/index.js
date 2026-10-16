// 词境后端：认证、作品、生成
// 绑定：env.cijing_db (D1) / env.AI_API_KEY / env.RESEND_API_KEY（secret）
//       env.AI_BASE_URL / env.AI_MODEL / env.ALLOWED_ORIGIN / env.MAIL_FROM（var）

const defaultHeaders = { "Content-Type": "application/json; charset=utf-8" };

function corsHeaders(request, env) {
  const requestedOrigin = request.headers.get("Origin") || "";
  const allowedOrigin = env.ALLOWED_ORIGIN || "*";
  return {
    ...defaultHeaders,
    "Access-Control-Allow-Origin":
      allowedOrigin === "*" || allowedOrigin === requestedOrigin ? requestedOrigin || "*" : allowedOrigin,
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    Vary: "Origin",
  };
}

function json(data, status, request, env) {
  return new Response(JSON.stringify(data), { status, headers: corsHeaders(request, env) });
}

function cleanText(value, maxLength) {
  return String(value || "").trim().slice(0, maxLength);
}

function extractJson(text) {
  const raw = String(text || "").trim();
  try {
    return JSON.parse(raw);
  } catch {
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) throw new Error("模型没有返回有效 JSON");
    return JSON.parse(match[0]);
  }
}

// ---------- 加密与标识 ----------

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function randomHex(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);   // 必须用 CSPRNG，不能用 Math.random
  return bytesToHex(bytes);
}

function makeId(prefix) {
  return `${prefix}_${randomHex(12)}`;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return bytesToHex(new Uint8Array(digest));
}

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBytes(saltHex), iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

// 定长比较，避免用 === 泄漏前缀匹配长度
function safeEqual(a, b) {
  const left = String(a || "");
  const right = String(b || "");
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return diff === 0;
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

// 邮箱验证码是否启用。关闭时：注册免验证码、登录只走密码。
// 用户体系与作品隔离与此无关，两者都完整保留。
function emailOtpRequired(env) {
  return env.EMAIL_OTP_ENABLED === "true";
}

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;   // 30 天
const OTP_TTL_MS = 5 * 60 * 1000;                  // 5 分钟
const OTP_RESEND_MS = 60 * 1000;                   // 同邮箱 60 秒内不重发
const OTP_MAX_ATTEMPTS = 5;

// ---------- 鉴权 ----------

async function currentUser(request, env) {
  const header = request.headers.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return null;

  const session = await env.cijing_db
    .prepare("SELECT user_id, expires_at FROM sessions WHERE token = ?")
    .bind(token)
    .first();
  if (!session) return null;

  if (Number(session.expires_at) < Date.now()) {
    await env.cijing_db.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return null;
  }

  const user = await env.cijing_db
    .prepare("SELECT id, email, name, plan, quota_total, quota_used, created_at FROM users WHERE id = ?")
    .bind(session.user_id)
    .first();
  if (!user) return null;
  return { user, token };
}

async function createSession(env, userId) {
  const token = randomHex(32);   // 256 位
  const now = Date.now();
  await env.cijing_db
    .prepare("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
    .bind(token, userId, now, now + SESSION_TTL_MS)
    .run();
  return token;
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    plan: user.plan,
    quotaTotal: Number(user.quota_total),
    quotaUsed: Number(user.quota_used),
    quotaLeft: Math.max(0, Number(user.quota_total) - Number(user.quota_used)),
    createdAt: Number(user.created_at),
  };
}

// ---------- 邀请码 ----------

async function loadInvite(env, code) {
  if (!code) return null;
  return env.cijing_db.prepare("SELECT * FROM invite_codes WHERE code = ?").bind(code).first();
}

function inviteUsable(invite) {
  if (!invite) return "邀请码不存在";
  if (Number(invite.used_count) >= Number(invite.max_uses)) return "邀请码已用完";
  if (invite.expires_at && Number(invite.expires_at) < Date.now()) return "邀请码已过期";
  return null;
}

// ---------- 邮箱验证码 ----------

async function sendOtpEmail(env, email, code) {
  if (!env.RESEND_API_KEY) {
    throw new Error("邮件服务未配置（缺少 RESEND_API_KEY）");
  }
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
    },
    body: JSON.stringify({
      from: env.MAIL_FROM || "词境 <onboarding@resend.dev>",
      to: [email],
      subject: `词境验证码 ${code}`,
      text: `你的验证码是 ${code}，5 分钟内有效。\n\n如果不是你本人操作，请忽略这封邮件。`,
    }),
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.message || `邮件发送失败（${res.status}）`);
  }
}

async function issueOtp(env, email, purpose) {
  const existing = await env.cijing_db
    .prepare("SELECT sent_at FROM otp_codes WHERE email = ? AND purpose = ?")
    .bind(email, purpose)
    .first();
  if (existing && Date.now() - Number(existing.sent_at) < OTP_RESEND_MS) {
    const wait = Math.ceil((OTP_RESEND_MS - (Date.now() - Number(existing.sent_at))) / 1000);
    return { error: `请 ${wait} 秒后再试` };
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const now = Date.now();
  await env.cijing_db
    .prepare(
      `INSERT INTO otp_codes (email, purpose, code_hash, expires_at, attempts, sent_at)
       VALUES (?, ?, ?, ?, 0, ?)
       ON CONFLICT(email, purpose) DO UPDATE SET
         code_hash = excluded.code_hash, expires_at = excluded.expires_at,
         attempts = 0, sent_at = excluded.sent_at`
    )
    .bind(email, purpose, await sha256Hex(`${code}:${email}`), now + OTP_TTL_MS, now)
    .run();

  // 开发模式跳过真实发信。OTP_DEV_MODE 只写在 .dev.vars（已被 gitignore、不会被部署），
  // 生产环境读不到它，因此这个分支在线上不可达。
  if (env.OTP_DEV_MODE !== "true") {
    await sendOtpEmail(env, email, code);
  }
  return { ok: true, code };
}

async function verifyOtp(env, email, purpose, code) {
  const row = await env.cijing_db
    .prepare("SELECT * FROM otp_codes WHERE email = ? AND purpose = ?")
    .bind(email, purpose)
    .first();
  if (!row) return "验证码不存在或已过期";
  if (Number(row.expires_at) < Date.now()) return "验证码已过期";
  if (Number(row.attempts) >= OTP_MAX_ATTEMPTS) return "尝试次数过多，请重新获取";

  const expected = await sha256Hex(`${cleanText(code, 10)}:${email}`);
  if (!safeEqual(expected, row.code_hash)) {
    await env.cijing_db
      .prepare("UPDATE otp_codes SET attempts = attempts + 1 WHERE email = ? AND purpose = ?")
      .bind(email, purpose)
      .run();
    return "验证码不正确";
  }

  await env.cijing_db
    .prepare("DELETE FROM otp_codes WHERE email = ? AND purpose = ?")
    .bind(email, purpose)
    .run();
  return null;
}

// ---------- 小说生成 ----------

function buildPrompt(input) {
  const words = input.words.join(", ");
  const tropes = input.tropes.join("、") || "自然推进";
  const setup = input.storySetup || "请围绕词单自由设计一个有明确冲突和收束的故事。";
  return `你是“词境”的英语词汇复习小说编辑。请根据以下配置创作一篇中文短篇复习小说。

小说大类：${input.genre}
细分题材：${input.subgenre}
核心剧情梗：${tropes}
剧情设定：${setup}
目标单词：${words}

硬性要求：
1. 正文必须自然包含全部目标单词，每个单词至少出现 2 次，保持英文原形、小写拼写，不要拆写。
2. 正文使用中文叙事，英文目标单词自然嵌入句子，不要把单词集中堆在一起。
3. 生成约 800 至 1400 个中文字符，有开端、冲突、推进和结尾。
4. 不要输出 Markdown，不要加粗标记，不要解释创作过程。
5. 正文的段落之间用空行分隔，不要编号，不要在段首加标点。
6. 只返回一个合法 JSON 对象，字段必须是：
{"title":"标题","hook":"一句话简介","summary":"不超过120字的简介","content":"小说正文","vocab":[{"word":"原形小写","pos":"词性缩写","meaning":"中文语境释义","forms":["正文中出现的变形"]}]}
7. vocab 必须为每一个目标单词返回一条记录，顺序与上面「目标单词」给出的顺序完全一致，不多不少。
8. meaning 不超过 40 个中文字符：先写词典义，再用「这里指……」结合本篇正文的具体情节补充说明。不要复制粘贴正文原句。
9. pos 使用 n. / v. / adj. / adv. / prep. 等缩写，多个词性用 / 连接，总长不超过 8 个字符。
10. forms 只填正文中真实出现过的变形（把原形也写进去），最多 6 个；正文里没有变形就返回空数组。
`;
}

function normalizeVocab(rawVocab, words) {
  const byWord = new Map();
  const push = (entry) => {
    if (!entry || typeof entry !== "object") return;
    const key = cleanText(entry.word, 40).toLowerCase();
    if (!key) return;
    byWord.set(key, {
      pos: cleanText(entry.pos, 12),
      meaning: cleanText(entry.meaning, 80),
      forms: Array.isArray(entry.forms)
        ? entry.forms.map((item) => cleanText(item, 30).toLowerCase()).filter(Boolean).slice(0, 6)
        : [],
    });
  };

  if (Array.isArray(rawVocab)) {
    rawVocab.forEach(push);
  } else if (rawVocab && typeof rawVocab === "object") {
    Object.entries(rawVocab).forEach(([key, value]) => push({ word: key, ...(value || {}) }));
  }

  return words.map((word) => {
    const hit = byWord.get(word.toLowerCase()) || {};
    return { word, pos: hit.pos || "", meaning: hit.meaning || "", forms: hit.forms || [] };
  });
}

// ---------- 作品序列化 ----------

function workToJson(row, viewerId) {
  return {
    id: row.id,
    title: row.title,
    genre: row.genre,
    subgenre: row.subgenre,
    tropes: safeParse(row.tropes, []),
    tag: row.subgenre || row.genre,
    hook: row.hook || "",
    summary: row.summary || "",
    count: `${safeParse(row.words, []).length} 个词 · 全文阅读`,
    words: safeParse(row.words, []),
    reader: String(row.content || "").split(/\n{1,}/).map((s) => s.trim()).filter(Boolean),
    vocab: safeParse(row.vocab, {}),
    visibility: row.visibility,
    publishedAt: row.published_at ? Number(row.published_at) : null,
    createdAt: Number(row.created_at),
    authorId: row.user_id,
    authorName: row.author_name || "",
    mine: viewerId ? row.user_id === viewerId : false,
  };
}

function safeParse(value, fallback) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

// ---------- 路由处理 ----------

async function handleInviteCheck(request, env) {
  const body = await request.json().catch(() => ({}));
  const invite = await loadInvite(env, cleanText(body.code, 40).toUpperCase());
  const reason = inviteUsable(invite);
  return json(reason ? { ok: false, error: reason } : { ok: true, plan: invite.plan }, 200, request, env);
}

async function handleSendCode(request, env) {
  // 关闭验证码时直接拒绝，避免有人借此触发邮件发送
  if (!emailOtpRequired(env)) {
    return json({ error: "当前未开启邮箱验证码，请直接注册或使用密码登录" }, 400, request, env);
  }
  const body = await request.json().catch(() => ({}));
  const email = normalizeEmail(body.email);
  const purpose = body.purpose === "register" ? "register" : "login";
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ error: "邮箱格式不正确" }, 400, request, env);
  }

  if (purpose === "register") {
    const invite = await loadInvite(env, cleanText(body.inviteCode, 40).toUpperCase());
    const reason = inviteUsable(invite);
    if (reason) return json({ error: reason }, 400, request, env);
    const taken = await env.cijing_db.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
    if (taken) return json({ error: "该邮箱已注册，请直接登录" }, 409, request, env);
  }

  try {
    const result = await issueOtp(env, email, purpose);
    if (result.error) return json({ error: result.error }, 429, request, env);
    // 本地开发逃生口：把验证码直接回传，方便没有邮件服务时测注册。
    // OTP_DEV_MODE 不存在于生产环境（只在 .dev.vars 里），线上分支不可达。
    if (env.OTP_DEV_MODE === "true") {
      return json({ ok: true, devCode: result.code }, 200, request, env);
    }
  } catch (error) {
    return json({ error: error.message || "验证码发送失败" }, 502, request, env);
  }
  return json({ ok: true }, 200, request, env);
}

async function handleRegister(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = normalizeEmail(body.email);
  const name = cleanText(body.name, 24) || "词境作者";
  const password = String(body.password || "");

  if (password.length < 6) return json({ error: "密码至少 6 位" }, 400, request, env);

  const invite = await loadInvite(env, cleanText(body.inviteCode, 40).toUpperCase());
  const reason = inviteUsable(invite);
  if (reason) return json({ error: reason }, 400, request, env);

  const taken = await env.cijing_db.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (taken) return json({ error: "该邮箱已注册，请直接登录" }, 409, request, env);

  if (emailOtpRequired(env)) {
    const otpError = await verifyOtp(env, email, "register", body.code);
    if (otpError) return json({ error: otpError }, 400, request, env);
  }

  const userId = makeId("u");
  const salt = randomHex(16);
  const passwordHash = await hashPassword(password, salt);
  const now = Date.now();

  // 先占用邀请码再建用户：并发下若名额已满则回滚，避免超额放行
  const claim = await env.cijing_db
    .prepare("UPDATE invite_codes SET used_count = used_count + 1 WHERE code = ? AND used_count < max_uses")
    .bind(invite.code)
    .run();
  if (!claim.meta || claim.meta.changes === 0) {
    return json({ error: "邀请码已用完" }, 400, request, env);
  }

  await env.cijing_db
    .prepare(
      `INSERT INTO users (id, email, name, password_hash, password_salt, plan, quota_total, quota_used, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`
    )
    .bind(userId, email, name, passwordHash, salt, invite.plan, Number(invite.quota) || 5, now)
    .run();

  const token = await createSession(env, userId);
  const user = await env.cijing_db
    .prepare("SELECT id, email, name, plan, quota_total, quota_used, created_at FROM users WHERE id = ?")
    .bind(userId)
    .first();
  return json({ ok: true, token, user: publicUser(user) }, 200, request, env);
}

async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const email = normalizeEmail(body.email);
  const password = String(body.password || "");
  const code = cleanText(body.code, 10);

  const user = await env.cijing_db.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  // 统一文案，不区分「邮箱不存在」与「密码错误」，防账号枚举
  const generic = "邮箱或凭证不正确";

  if (password) {
    if (!user || !user.password_hash) return json({ error: generic }, 401, request, env);
    const hash = await hashPassword(password, user.password_salt);
    if (!safeEqual(hash, user.password_hash)) return json({ error: generic }, 401, request, env);
  } else if (code) {
    if (!emailOtpRequired(env)) return json({ error: "当前未开启验证码登录，请用密码登录" }, 400, request, env);
    if (!user) return json({ error: generic }, 401, request, env);
    const otpError = await verifyOtp(env, email, "login", code);
    if (otpError) return json({ error: otpError }, 401, request, env);
  } else {
    return json({ error: "请提供密码或验证码" }, 400, request, env);
  }

  const token = await createSession(env, user.id);
  return json({ ok: true, token, user: publicUser(user) }, 200, request, env);
}

async function handleGenerate(request, env, auth) {
  const { user } = auth;

  if (Number(user.quota_used) >= Number(user.quota_total)) {
    return json(
      { error: `本次配额已用完（${user.quota_total} 次）。升级后可继续创作。`, quotaLeft: 0 },
      402,
      request,
      env
    );
  }

  const input = await request.json().catch(() => ({}));
  const words = Array.isArray(input.words)
    ? input.words.map((word) => cleanText(word, 40).toLowerCase()).filter(Boolean).slice(0, 50)
    : [];
  if (!words.length) return json({ error: "至少需要一个目标单词" }, 400, request, env);

  const genre = cleanText(input.genre, 40) || "悬疑刑侦";
  const subgenre = cleanText(input.subgenre, 40) || "密室凶案";
  const tropes = Array.isArray(input.tropes)
    ? input.tropes.map((item) => cleanText(item, 40)).slice(0, 3)
    : [];
  const visibility = input.visibility === "public" ? "public" : "private";

  const baseUrl = (env.AI_BASE_URL || "https://api.deepseek.com").replace(/\/+$/, "");
  const model = env.AI_MODEL || "deepseek-chat";

  let upstream;
  try {
    upstream = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${env.AI_API_KEY}` },
      body: JSON.stringify({
        model,
        temperature: 0.8,
        max_tokens: 8000,
        messages: [
          { role: "system", content: "你必须遵守用户给出的词汇覆盖规则，并且只返回合法 JSON。" },
          {
            role: "user",
            content: buildPrompt({
              words,
              genre,
              subgenre,
              tropes,
              storySetup: cleanText(input.storySetup, 600),
            }),
          },
        ],
      }),
    });
  } catch (error) {
    return json({ error: "无法连接生成服务，请稍后重试" }, 502, request, env);
  }

  const upstreamBody = await upstream.json().catch(() => ({}));
  if (!upstream.ok) {
    return json(
      { error: upstreamBody.error?.message || `AI 服务返回 ${upstream.status}` },
      502,
      request,
      env
    );
  }
  if (upstreamBody.choices?.[0]?.finish_reason === "length") {
    return json({ error: "生成内容过长被截断，请减少词量后重试" }, 502, request, env);
  }

  const message = upstreamBody.choices?.[0]?.message?.content;
  let result;
  try {
    result = extractJson(message);
  } catch (error) {
    return json({ error: error.message || "模型返回内容无法解析" }, 502, request, env);
  }
  if (!result.title || !result.content) {
    return json({ error: "AI 返回内容缺少标题或正文" }, 502, request, env);
  }

  // 生成成功才落库并扣配额：失败不该消耗用户的额度
  const workId = makeId("w");
  const now = Date.now();
  await env.cijing_db
    .prepare(
      `INSERT INTO works (id, user_id, title, genre, subgenre, tropes, hook, summary, content,
                          words, vocab, visibility, published_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      workId,
      user.id,
      cleanText(result.title, 80),
      genre,
      subgenre,
      JSON.stringify(tropes),
      cleanText(result.hook, 220),
      cleanText(result.summary, 600),
      cleanText(result.content, 20000),
      JSON.stringify(words),
      JSON.stringify(normalizeVocab(result.vocab, words)),
      visibility,
      visibility === "public" ? now : null,
      now
    )
    .run();

  await env.cijing_db
    .prepare("UPDATE users SET quota_used = quota_used + 1 WHERE id = ?")
    .bind(user.id)
    .run();

  const row = await env.cijing_db
    .prepare("SELECT w.*, u.name AS author_name FROM works w JOIN users u ON u.id = w.user_id WHERE w.id = ?")
    .bind(workId)
    .first();

  const fresh = await env.cijing_db
    .prepare("SELECT quota_total, quota_used FROM users WHERE id = ?")
    .bind(user.id)
    .first();

  return json(
    {
      ok: true,
      work: workToJson(row, user.id),
      quotaLeft: Math.max(0, Number(fresh.quota_total) - Number(fresh.quota_used)),
    },
    200,
    request,
    env
  );
}

// 把本机既有作品迁入账号。不消耗配额 —— 这不是一次生成，而是把已有内容搬到服务器。
async function handleCreateWork(request, env, auth) {
  const body = await request.json().catch(() => ({}));
  const title = cleanText(body.title, 80);
  const content = cleanText(body.content, 20000);
  if (!title || !content) return json({ error: "标题与正文不能为空" }, 400, request, env);

  const words = Array.isArray(body.words)
    ? body.words.map((word) => cleanText(word, 40).toLowerCase()).filter(Boolean).slice(0, 50)
    : [];
  const genre = cleanText(body.genre, 40) || "悬疑刑侦";
  const subgenre = cleanText(body.subgenre, 40) || "密室凶案";
  const vocab = body.vocab && typeof body.vocab === "object" ? body.vocab : {};
  const now = Date.now();
  const workId = makeId("w");

  await env.cijing_db
    .prepare(
      `INSERT INTO works (id, user_id, title, genre, subgenre, tropes, hook, summary, content,
                          words, vocab, visibility, published_at, created_at)
       VALUES (?, ?, ?, ?, ?, '[]', ?, ?, ?, ?, ?, 'private', NULL, ?)`
    )
    .bind(
      workId,
      auth.user.id,
      title,
      genre,
      subgenre,
      cleanText(body.hook, 220),
      cleanText(body.summary, 600),
      content,
      JSON.stringify(words),
      JSON.stringify(vocab),
      now
    )
    .run();

  const row = await env.cijing_db
    .prepare("SELECT w.*, u.name AS author_name FROM works w JOIN users u ON u.id = w.user_id WHERE w.id = ?")
    .bind(workId)
    .first();
  return json({ ok: true, work: workToJson(row, auth.user.id) }, 200, request, env);
}

async function handleListWorks(request, env, url) {
  const auth = await currentUser(request, env);
  const viewerId = auth ? auth.user.id : null;
  const scope = url.searchParams.get("scope") || "feed";
  const genre = cleanText(url.searchParams.get("genre"), 40);
  const limit = Math.min(60, Math.max(1, Number(url.searchParams.get("limit")) || 24));

  let sql;
  let params;

  if (scope === "mine") {
    if (!viewerId) return json({ error: "请先登录" }, 401, request, env);
    sql = `SELECT w.*, u.name AS author_name FROM works w JOIN users u ON u.id = w.user_id
           WHERE w.user_id = ? ORDER BY w.created_at DESC LIMIT ?`;
    params = [viewerId, limit];
  } else {
    // feed / new 只返回公开作品
    const order = scope === "new" ? "w.published_at DESC" : "w.published_at DESC";
    sql = `SELECT w.*, u.name AS author_name FROM works w JOIN users u ON u.id = w.user_id
           WHERE w.visibility = 'public' ${genre ? "AND w.genre = ?" : ""}
           ORDER BY ${order} LIMIT ?`;
    params = genre ? [genre, limit] : [limit];
  }

  const { results } = await env.cijing_db.prepare(sql).bind(...params).all();
  return json(
    { ok: true, works: (results || []).map((row) => workToJson(row, viewerId)) },
    200,
    request,
    env
  );
}

async function handleGetWork(request, env, workId) {
  const auth = await currentUser(request, env);
  const viewerId = auth ? auth.user.id : null;
  const row = await env.cijing_db
    .prepare("SELECT w.*, u.name AS author_name FROM works w JOIN users u ON u.id = w.user_id WHERE w.id = ?")
    .bind(workId)
    .first();
  if (!row) return json({ error: "作品不存在" }, 404, request, env);
  // 私密作品只有作者本人能读
  if (row.visibility !== "public" && row.user_id !== viewerId) {
    return json({ error: "作品不存在" }, 404, request, env);
  }
  return json({ ok: true, work: workToJson(row, viewerId) }, 200, request, env);
}

async function handleUpdateWork(request, env, workId, auth) {
  const row = await env.cijing_db.prepare("SELECT * FROM works WHERE id = ?").bind(workId).first();
  if (!row) return json({ error: "作品不存在" }, 404, request, env);
  if (row.user_id !== auth.user.id) return json({ error: "无权操作该作品" }, 403, request, env);

  const body = await request.json().catch(() => ({}));
  if (body.visibility !== undefined) {
    const visibility = body.visibility === "public" ? "public" : "private";
    const publishedAt = visibility === "public" ? Date.now() : null;
    await env.cijing_db
      .prepare("UPDATE works SET visibility = ?, published_at = ? WHERE id = ?")
      .bind(visibility, publishedAt, workId)
      .run();
  }

  const fresh = await env.cijing_db
    .prepare("SELECT w.*, u.name AS author_name FROM works w JOIN users u ON u.id = w.user_id WHERE w.id = ?")
    .bind(workId)
    .first();
  return json({ ok: true, work: workToJson(fresh, auth.user.id) }, 200, request, env);
}

async function handleDeleteWork(request, env, workId, auth) {
  const row = await env.cijing_db.prepare("SELECT user_id FROM works WHERE id = ?").bind(workId).first();
  if (!row) return json({ error: "作品不存在" }, 404, request, env);
  if (row.user_id !== auth.user.id) return json({ error: "无权操作该作品" }, 403, request, env);
  await env.cijing_db.prepare("DELETE FROM works WHERE id = ?").bind(workId).run();
  return json({ ok: true }, 200, request, env);
}

// ---------- 入口 ----------

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method;

    try {
      if (path === "/api/config" && method === "GET") {
        return json({ ok: true, emailOtp: emailOtpRequired(env) }, 200, request, env);
      }
      if (path === "/api/invite/check" && method === "POST") return await handleInviteCheck(request, env);
      if (path === "/api/auth/send-code" && method === "POST") return await handleSendCode(request, env);
      if (path === "/api/auth/register" && method === "POST") return await handleRegister(request, env);
      if (path === "/api/auth/login" && method === "POST") return await handleLogin(request, env);

      // 以下接口都需要登录。
      // 注意 GET /api/works/:id 不在此列 —— 游客应能读公开作品，可见性由处理器内部判断。
      const needsAuth = path === "/api/me"
        || path === "/api/generate"
        || path === "/api/auth/logout"
        || (path === "/api/works" && (url.searchParams.get("scope") === "mine" || method === "POST"))
        || (path.startsWith("/api/works/") && method !== "GET");

      const auth = await currentUser(request, env);
      if (needsAuth && !auth) return json({ error: "请先登录" }, 401, request, env);

      if (path === "/api/me" && method === "GET") {
        return json({ ok: true, user: publicUser(auth.user) }, 200, request, env);
      }
      if (path === "/api/auth/logout" && method === "POST") {
        await env.cijing_db.prepare("DELETE FROM sessions WHERE token = ?").bind(auth.token).run();
        return json({ ok: true }, 200, request, env);
      }
      if (path === "/api/generate" && method === "POST") {
        return await handleGenerate(request, env, auth);
      }
      if (path === "/api/works" && method === "GET") {
        return await handleListWorks(request, env, url);
      }
      if (path === "/api/works" && method === "POST") {
        return await handleCreateWork(request, env, auth);
      }

      const workMatch = path.match(/^\/api\/works\/([A-Za-z0-9_-]+)$/);
      if (workMatch) {
        const workId = workMatch[1];
        if (method === "GET") return await handleGetWork(request, env, workId);
        if (method === "PATCH") return await handleUpdateWork(request, env, workId, auth);
        if (method === "DELETE") return await handleDeleteWork(request, env, workId, auth);
      }

      return json({ error: "Not found" }, 404, request, env);
    } catch (error) {
      return json({ error: error.message || "服务器错误" }, 500, request, env);
    }
  },
};
