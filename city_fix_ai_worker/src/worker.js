export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);

    // CORS 预检
    if (req.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(req) });
    }

    // 健康检查（可选）：GET /ai/vision?ping=1
    if (url.pathname === "/ai/vision" && req.method === "GET") {
      return json({ ok: true, msg: "cityfix-ai-worker alive" }, 200, req);
    }

    if (url.pathname !== "/ai/vision") {
      return new Response("Not Found", { status: 404, headers: corsHeaders(req) });
    }

    if (req.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405, headers: corsHeaders(req) });
    }

    try {
      const form = await req.formData();
      const file = form.get("image");
      const lang = (form.get("lang") || "zh").toString().toLowerCase();

      if (!file || !(file instanceof File)) {
        return json({ error: "No image" }, 400, req);
      }

      // 安全限制：大小 ≤ 8MB；只接受常见图片类型
      const ALLOWED = ["image/jpeg", "image/png", "image/webp", "image/heic", "image/heif"];
      if (!ALLOWED.includes(file.type)) {
        return json({ error: `Unsupported content-type: ${file.type}` }, 415, req);
      }
      if (file.size > 8 * 1024 * 1024) {
        return json({ error: "Payload too large (>8MB)" }, 413, req);
      }

      // 读取文件并转 base64 data URL
      const ab = await file.arrayBuffer();
      const b64 = toDataURL(ab, file.type);

      // 提示词（中/英）
      const prompt =
        lang.startsWith("zh")
          ? `你是城市报修助手。只从下列类型中选择一类，并返回 JSON：
- Pothole（坑洞）, Road crack（路面裂缝）, Blocked drain（下水道堵塞）
- Streetlight outage（路灯不亮）, Traffic sign damage（交通标志损坏）
- Fallen tree / Broken branch（倒树/断枝）, Illegal dumping（垃圾堆放）
- Graffiti/Vandalism（涂鸦/破坏）, Water leak（漏水）
- Sidewalk damage（人行道破损）, Building facade hazard（外立面脱落风险）
输出: {"type":英文,"confidence":0~1,"severity":"low|medium|high","short_description":"<=24字","long_description":"1-2句"}`
          : `You are a civic maintenance assistant. Pick ONE type from the list and return JSON with {type, confidence, severity, short_description, long_description}. Types: Pothole, Road crack, Blocked drain, Streetlight outage, Traffic sign damage, Fallen tree, Broken branch, Illegal dumping, Graffiti/Vandalism, Water leak, Sidewalk damage, Building facade hazard.`;

      // 组装 OpenAI 请求体（可换成你偏好的模型/厂商）
      const payload = {
        model: "gpt-4o-mini",
        temperature: 0.2,
        response_format: { type: "json_object" },
        messages: [
          {
            role: "user",
            content: [
              { type: "text", text: prompt },
              { type: "image_url", image_url: { url: b64 } },
            ],
          },
        ],
      };

      // 调 OpenAI（密钥放在 Worker Secret）
      const r = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.OPENAI_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (!r.ok) {
        const txt = await safeText(r);
        return json({ error: "Upstream error", status: r.status, detail: txt?.slice(0, 200) }, 502, req);
      }

      // 直接把 JSON 返回给前端
      const data = await r.json();
      const content = data?.choices?.[0]?.message?.content || "{}";
      // 尝试解析成对象；解析失败就原样返回字符串
      let out;
      try { out = JSON.parse(content); } catch { out = { raw: content }; }

      return json(out, 200, req);
    } catch (e) {
      return json({ error: e?.message || "Unknown error" }, 500, req);
    }
  },
};

/** 工具函数 */
function corsHeaders(req) {
  const origin = req.headers.get("Origin") || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Vary": "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "POST,GET,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}
function json(obj, status, req) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...corsHeaders(req), "Content-Type": "application/json; charset=utf-8" },
  });
}
async function safeText(resp) {
  try { return await resp.text(); } catch { return ""; }
}
function toDataURL(arrayBuffer, mime = "application/octet-stream") {
  const bytes = new Uint8Array(arrayBuffer);
  // 分块避免一次性拼接过大
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  const base64 = btoa(binary);
  return `data:${mime};base64,${base64}`;
}
