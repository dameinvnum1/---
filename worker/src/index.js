const defaultHeaders = {
  "Content-Type": "application/json; charset=utf-8",
};

function corsHeaders(request, env) {
  const requestedOrigin = request.headers.get("Origin") || "";
  const allowedOrigin = env.ALLOWED_ORIGIN || "*";
  return {
    ...defaultHeaders,
    "Access-Control-Allow-Origin":
      allowedOrigin === "*" || allowedOrigin === requestedOrigin ? requestedOrigin || "*" : allowedOrigin,
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

function json(data, status, request, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders(request, env),
  });
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
    // 兜底：模型可能返回 {"word": {...}} 的对象形态
    Object.entries(rawVocab).forEach(([key, value]) => push({ word: key, ...(value || {}) }));
  }

  // 以请求词表为准输出，保证长度与顺序完全可控：模型漏词也不会造成前后端长度不匹配
  return words.map((word) => {
    const hit = byWord.get(word.toLowerCase()) || {};
    return {
      word,
      pos: hit.pos || "",
      meaning: hit.meaning || "",
      forms: hit.forms || [],
    };
  });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }
    const url = new URL(request.url);
    if (url.pathname !== "/api/generate" || request.method !== "POST") {
      return json({ error: "Not found" }, 404, request, env);
    }
    if (!env.AI_API_KEY) {
      return json({ error: "AI_API_KEY 尚未配置" }, 500, request, env);
    }

    try {
      const input = await request.json();
      const words = Array.isArray(input.words)
        ? input.words.map((word) => cleanText(word, 40)).filter(Boolean).slice(0, 50)
        : [];
      if (!words.length) return json({ error: "至少需要一个目标单词" }, 400, request, env);

      const baseUrl = (env.AI_BASE_URL || "https://api.deepseek.com").replace(/\/+$/, "");
      const model = env.AI_MODEL || "deepseek-chat";
      const upstream = await fetch(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${env.AI_API_KEY}`,
        },
        body: JSON.stringify({
          model,
          temperature: 0.8,
          max_tokens: 8000,
          messages: [
            {
              role: "system",
              content: "你必须遵守用户给出的词汇覆盖规则，并且只返回合法 JSON。",
            },
            {
              role: "user",
              content: buildPrompt({
                words,
                genre: cleanText(input.genre, 40),
                subgenre: cleanText(input.subgenre, 40),
                tropes: Array.isArray(input.tropes)
                  ? input.tropes.map((item) => cleanText(item, 40)).slice(0, 3)
                  : [],
                storySetup: cleanText(input.storySetup, 600),
              }),
            },
          ],
        }),
      });
      const upstreamBody = await upstream.json().catch(() => ({}));
      if (!upstream.ok) {
        return json(
          { error: upstreamBody.error?.message || `AI 服务返回 ${upstream.status}` },
          502,
          request,
          env
        );
      }

      // 被 max_tokens 截断时 extractJson 会抛出难以理解的解析错误，这里先给出可读原因
      if (upstreamBody.choices?.[0]?.finish_reason === "length") {
        return json({ error: "生成内容过长被截断，请减少词量后重试" }, 502, request, env);
      }

      const message = upstreamBody.choices?.[0]?.message?.content;
      const result = extractJson(message);
      if (!result.title || !result.content) {
        return json({ error: "AI 返回内容缺少标题或正文" }, 502, request, env);
      }
      return json(
        {
          title: cleanText(result.title, 80),
          hook: cleanText(result.hook, 220),
          summary: cleanText(result.summary, 600),
          content: cleanText(result.content, 20000),
          vocab: normalizeVocab(result.vocab, words),
        },
        200,
        request,
        env
      );
    } catch (error) {
      return json({ error: error.message || "生成失败" }, 500, request, env);
    }
  },
};
