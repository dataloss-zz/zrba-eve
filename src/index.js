const CLIENT_ID = "f6080d22aeda4a90a3f20c5906d83037";
// Add leader character IDs here (as strings).
const LEADER_IDS = new Set([
  // "123456789",
]);

function cors() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function charIdFromToken(token) {
  try {
    const payload = token.split(".")[1];
    const claims = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    return String(claims.sub || "").split(":").pop();
  } catch {
    return null;
  }
}

function tokenFrom(request) {
  return (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
}

async function exchangeToken(data) {
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code: data.code,
    client_id: CLIENT_ID,
    code_verifier: data.code_verifier,
  });
  const tokenRes = await fetch("https://login.eveonline.com/v2/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form,
  });
  const body = await tokenRes.text();
  return new Response(body, {
    status: tokenRes.status,
    headers: { "Content-Type": "application/json", ...cors() },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors() });
    }

    if (url.pathname === "/exchange" && request.method === "POST") {
      try {
        return await exchangeToken(await request.json());
      } catch (err) {
        return new Response(JSON.stringify({ error: String(err) }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...cors() },
        });
      }
    }

    if (url.pathname === "/me" && request.method === "GET") {
      const charId = charIdFromToken(tokenFrom(request));
      if (!charId) {
        return new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401,
          headers: { "Content-Type": "application/json", ...cors() },
        });
      }
      return new Response(JSON.stringify({
        character_id: charId,
        is_leader: LEADER_IDS.has(charId),
      }), { headers: { "Content-Type": "application/json", ...cors() } });
    }

    if (url.pathname === "/applications" && request.method === "POST") {
      try {
        const charId = charIdFromToken(tokenFrom(request));
        if (!charId) {
          return new Response(JSON.stringify({ error: "unauthorized" }), {
            status: 401,
            headers: { "Content-Type": "application/json", ...cors() },
          });
        }
        const profile = await request.json();
        profile.character_id = charId;
        profile.submitted_at = new Date().toISOString();
        const key = `app:${charId}:${Date.now()}`;
        await env.APPLICATIONS.put(key, JSON.stringify(profile));
        return new Response(JSON.stringify({ ok: true, key }), {
          headers: { "Content-Type": "application/json", ...cors() },
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: String(err) }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...cors() },
        });
      }
    }

    if (url.pathname === "/applications" && request.method === "GET") {
      const charId = charIdFromToken(tokenFrom(request));
      if (!charId || !LEADER_IDS.has(charId)) {
        return new Response(JSON.stringify({ error: "leaders only" }), {
          status: 403,
          headers: { "Content-Type": "application/json", ...cors() },
        });
      }
      const list = await env.APPLICATIONS.list({ prefix: "app:" });
      const apps = [];
      for (const k of list.keys) {
        const val = await env.APPLICATIONS.get(k.name);
        if (val) apps.push(JSON.parse(val));
      }
      apps.sort((a, b) => (b.submitted_at || "").localeCompare(a.submitted_at || ""));
      return new Response(JSON.stringify(apps), {
        headers: { "Content-Type": "application/json", ...cors() },
      });
    }

    if (url.pathname === "/callback") {
      return env.ASSETS.fetch(new Request(new URL("/", url), request));
    }

    return env.ASSETS.fetch(request);
  },
};
