const CLIENT_ID = "f6080d22aeda4a90a3f20c5906d83037";
const LEADER_NAMES = { "1655394838": "datalost" };
const LEADER_IDS = new Set(Object.keys(LEADER_NAMES));

function cors() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

let jwksCache = null;
let jwksCacheExpiresAt = 0;

function decodeBase64Url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  return atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
}

async function getJwks() {
  if (jwksCache && Date.now() < jwksCacheExpiresAt) return jwksCache;
  const metadataRes = await fetch("https://login.eveonline.com/.well-known/oauth-authorization-server");
  if (!metadataRes.ok) throw new Error("EVE SSO metadata unavailable");
  const metadata = await metadataRes.json();
  if (typeof metadata.jwks_uri !== "string" || !metadata.jwks_uri.startsWith("https://login.eveonline.com/")) {
    throw new Error("Invalid EVE SSO JWKS endpoint");
  }
  const jwksRes = await fetch(metadata.jwks_uri);
  if (!jwksRes.ok) throw new Error("EVE SSO signing keys unavailable");
  const jwks = await jwksRes.json();
  if (!Array.isArray(jwks.keys)) throw new Error("Invalid EVE SSO signing keys");
  jwksCache = jwks;
  jwksCacheExpiresAt = Date.now() + 5 * 60 * 1000;
  return jwksCache;
}

async function charIdFromToken(token, diagnostic = null) {
  const reject = (reason) => { if (diagnostic) diagnostic.reason = reason; return null; };
  try {
    if (typeof token !== "string") return reject("missing token");
    const parts = token.split(".");
    if (parts.length !== 3) return reject("invalid token format");
    const header = JSON.parse(decodeBase64Url(parts[0]));
    const claims = JSON.parse(decodeBase64Url(parts[1]));
    if (header.alg !== "RS256" || typeof header.kid !== "string") return reject("unsupported token signing algorithm");

    const now = Math.floor(Date.now() / 1000);
    if (!Number.isFinite(claims.exp) || claims.exp <= now) return reject("expired token");
    if (!["https://login.eveonline.com/", "https://login.eveonline.com", "login.eveonline.com"].includes(claims.iss)) return reject("unexpected token issuer");
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(CLIENT_ID)) return reject("token audience mismatch");
    if (typeof claims.sub !== "string" || !/^CHARACTER:EVE:\d+$/.test(claims.sub)) return reject("invalid character identity");

    const jwks = await getJwks();
    const jwk = jwks.keys.find(key => key.kid === header.kid && key.alg === "RS256" && key.kty === "RSA");
    if (!jwk) {
      jwksCache = null;
      jwksCacheExpiresAt = 0;
      return reject("signing key not found");
    }
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const signature = Uint8Array.from(decodeBase64Url(parts[2]), ch => ch.charCodeAt(0));
    const signedData = new TextEncoder().encode(parts[0] + "." + parts[1]);
    const validSignature = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, signedData);
    return validSignature ? claims.sub.split(":").pop() : reject("invalid token signature");
  } catch {
    return reject("token verification error");
  }
}

function tokenFrom(request) {
  return (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
}

const SESSION_SECONDS = 24 * 60 * 60;
function refreshCookie(token) {
  return "eve_refresh=" + encodeURIComponent(token) + "; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=" + SESSION_SECONDS;
}
function clearRefreshCookie() {
  return "eve_refresh=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0";
}
function refreshFromCookie(request) {
  const match = (request.headers.get("Cookie") || "").match(/(?:^|;\\s*)eve_refresh=([^;]*)/);
  try { return match ? decodeURIComponent(match[1]) : null; } catch { return null; }
}
function sameOriginRequest(request) {
  const origin = request.headers.get("Origin");
  return origin === new URL(request.url).origin;
}
async function refreshToken(request) {
  if (!sameOriginRequest(request)) return new Response(JSON.stringify({ error: "invalid origin" }), { status: 403, headers: { "Content-Type": "application/json" } });
  const refreshTokenValue = refreshFromCookie(request);
  if (!refreshTokenValue) return new Response(JSON.stringify({ error: "session expired" }), { status: 401, headers: { "Content-Type": "application/json" } });
  const form = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshTokenValue, client_id: CLIENT_ID });
  const result = await fetch("https://login.eveonline.com/v2/oauth/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form });
  const payload = await result.json();
  const headers = { "Content-Type": "application/json", "Cache-Control": "no-store" };
  if (!result.ok || !payload.access_token || !payload.refresh_token) {
    headers["Set-Cookie"] = clearRefreshCookie();
    return new Response(JSON.stringify({ error: "session expired; sign in again" }), { status: 401, headers });
  }
  headers["Set-Cookie"] = refreshCookie(payload.refresh_token);
  return new Response(JSON.stringify({ access_token: payload.access_token, expires_in: payload.expires_in }), { headers });
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
  let payload;
  try { payload = JSON.parse(body); } catch { payload = null; }
  const headers = { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors() };
  if (tokenRes.ok && payload?.refresh_token) {
    headers["Set-Cookie"] = refreshCookie(payload.refresh_token);
    delete payload.refresh_token;
  }
  return new Response(payload ? JSON.stringify(payload) : body, { status: tokenRes.status, headers });
}

async function canAccessSiteAdmin(token) {
  const characterId = await charIdFromToken(token);
  if (!characterId) return false;
  if (characterId === "1655394838") return true;
  try {
    const [leaderResponse, characterResponse, rolesResponse] = await Promise.all([
      fetch("https://esi.evetech.net/latest/characters/1655394838/"),
      fetch("https://esi.evetech.net/latest/characters/" + characterId + "/"),
      fetch("https://esi.evetech.net/latest/characters/" + characterId + "/roles/", {
        headers: { Authorization: "Bearer " + token }
      })
    ]);
    if (!leaderResponse.ok || !characterResponse.ok || !rolesResponse.ok) return false;
    const [leader, character, roles] = await Promise.all([
      leaderResponse.json(), characterResponse.json(), rolesResponse.json()
    ]);
    return leader.corporation_id === character.corporation_id &&
      Array.isArray(roles.roles) && roles.roles.includes("Director");
  } catch { return false; }
}

async function siteAdminPage(request, env) {
  const denied = () => new Response("Site.Admin access requires an authorized EVE Director or datalost.", {
    status: 403, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
  });
  const refresh = refreshFromCookie(request);
  if (!refresh) return denied();
  try {
    const form = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refresh, client_id: CLIENT_ID });
    const result = await fetch("https://login.eveonline.com/v2/oauth/token", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form
    });
    if (!result.ok) return denied();
    const payload = await result.json();
    if (!payload.access_token || !payload.refresh_token) return denied();
    const allowed = await canAccessSiteAdmin(payload.access_token);
    if (!allowed) {
      const response = denied();
      response.headers.set("Set-Cookie", refreshCookie(payload.refresh_token));
      return response;
    }
    const asset = await env.ASSETS.fetch(request);
    const headers = new Headers(asset.headers);
    headers.set("Cache-Control", "private, no-store");
    headers.set("Set-Cookie", refreshCookie(payload.refresh_token));
    return new Response(asset.body, { status: asset.status, headers });
  } catch { return denied(); }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors() });
    }

    if (url.pathname === "/refresh" && request.method === "POST") {
      try { return await refreshToken(request); }
      catch { return new Response(JSON.stringify({ error: "refresh unavailable" }), { status: 503, headers: { "Content-Type": "application/json" } }); }
    }
    if (url.pathname === "/logout" && request.method === "POST") {
      if (!sameOriginRequest(request)) return new Response(null, { status: 403 });
      return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json", "Set-Cookie": clearRefreshCookie() } });
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

    if (url.pathname === "/info.html" && request.method === "GET") {
      return siteAdminPage(request, env);
    }
    if (url.pathname === "/site-admin-access" && request.method === "GET") {
      const allowed = await canAccessSiteAdmin(tokenFrom(request));
      return Response.json({ allowed }, { headers: { "Cache-Control": "no-store" } });
    }

    if (url.pathname === "/me" && request.method === "GET") {
      const charId = await charIdFromToken(tokenFrom(request));
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
        const diagnostic = {};
        const charId = await charIdFromToken(tokenFrom(request), diagnostic);
        if (!charId) {
          return new Response(JSON.stringify({ error: "unauthorized: " + (diagnostic.reason || "token rejected") }), {
            status: 401,
            headers: { "Content-Type": "application/json", ...cors() },
          });
        }
        const profile = await request.json();
        profile.character_id = charId;
        profile.submitted_at = new Date().toISOString();
        profile.status = "pending";
        profile.decided_at = null;
        profile.decided_by = null;
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

    if (url.pathname === "/application-status" && request.method === "GET") {
      const charId = await charIdFromToken(tokenFrom(request));
      if (!charId) return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401, headers: { "Content-Type": "application/json", ...cors() },
      });
      const list = await env.APPLICATIONS.list({ prefix: `app:${charId}:` });
      const apps = [];
      for (const k of list.keys) {
        const value = await env.APPLICATIONS.get(k.name);
        if (value) apps.push({ ...JSON.parse(value), application_key: k.name });
      }
      apps.sort((a, b) => (b.submitted_at || "").localeCompare(a.submitted_at || ""));
      return new Response(JSON.stringify({
        application: apps[0] || null,
        recruitment_leaders: Object.entries(LEADER_NAMES).map(([id, name]) => ({ id, name })),
      }), { headers: { "Content-Type": "application/json", ...cors() } });
    }

    if (url.pathname === "/application-decision" && request.method === "POST") {
      const charId = await charIdFromToken(tokenFrom(request));
      if (!charId || !LEADER_IDS.has(charId)) return new Response(JSON.stringify({ error: "leaders only" }), {
        status: 403, headers: { "Content-Type": "application/json", ...cors() },
      });
      try {
        const body = await request.json();
        if (!body || !["accepted", "declined"].includes(body.status) ||
            typeof body.application_key !== "string" || !body.application_key.startsWith("app:")) {
          return new Response(JSON.stringify({ error: "invalid decision" }), {
            status: 400, headers: { "Content-Type": "application/json", ...cors() },
          });
        }
        const existing = await env.APPLICATIONS.get(body.application_key);
        if (!existing) return new Response(JSON.stringify({ error: "application not found" }), {
          status: 404, headers: { "Content-Type": "application/json", ...cors() },
        });
        const application = JSON.parse(existing);
        if ((application.status || "pending") !== "pending") return new Response(JSON.stringify({ error: "application is no longer pending" }), {
          status: 409, headers: { "Content-Type": "application/json", ...cors() },
        });
        application.status = body.status;
        // Each new decline starts a fresh discussion cycle; retain the review audit history.
        if (body.status === "declined") delete application.discussion;
        application.decided_at = new Date().toISOString();
        application.decided_by = charId;
        application.decided_by_name = LEADER_NAMES[charId];
        await env.APPLICATIONS.put(body.application_key, JSON.stringify(application));
        return new Response(JSON.stringify({ ok: true, status: application.status }), {
          headers: { "Content-Type": "application/json", ...cors() },
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: String(err) }), {
          status: 400, headers: { "Content-Type": "application/json", ...cors() },
        });
      }
    }

    if (url.pathname === "/application-discussion" && request.method === "POST") {
      const charId = await charIdFromToken(tokenFrom(request));
      if (!charId) return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json", ...cors() } });
      try {
        const body = await request.json();
        if (typeof body.summary !== "string" || body.summary.length > 1000 || !body.summary.trim() ||
            typeof body.leader_id !== "string" || !LEADER_IDS.has(body.leader_id)) {
          return new Response(JSON.stringify({ error: "choose a leader and enter a summary (maximum 1000 characters)" }), { status: 400, headers: { "Content-Type": "application/json", ...cors() } });
        }
        const list = await env.APPLICATIONS.list({ prefix: "app:" + charId + ":" });
        const apps = [];
        for (const k of list.keys) {
          const value = await env.APPLICATIONS.get(k.name);
          if (value) apps.push({ ...JSON.parse(value), application_key: k.name });
        }
        apps.sort((a, b) => (b.submitted_at || "").localeCompare(a.submitted_at || ""));
        const application = apps[0];
        if (!application || application.status !== "declined") return new Response(JSON.stringify({ error: "no declined application" }), { status: 409, headers: { "Content-Type": "application/json", ...cors() } });
        if (application.discussion?.summary) return new Response(JSON.stringify({ error: "discussion summary already submitted" }), { status: 409, headers: { "Content-Type": "application/json", ...cors() } });
        const applicationKey = application.application_key;
        application.discussion = { summary: body.summary.trim(), leader_id: body.leader_id, leader_name: LEADER_NAMES[body.leader_id], updated_at: new Date().toISOString() };
        delete application.application_key;
        await env.APPLICATIONS.put(applicationKey, JSON.stringify(application));
        return new Response(JSON.stringify({ ok: true, discussion: application.discussion }), { headers: { "Content-Type": "application/json", ...cors() } });
      } catch {
        return new Response(JSON.stringify({ error: "could not save discussion" }), { status: 400, headers: { "Content-Type": "application/json", ...cors() } });
      }
    }

    if (url.pathname === "/application-review" && request.method === "POST") {
      const charId = await charIdFromToken(tokenFrom(request));
      if (!charId || !LEADER_IDS.has(charId)) return new Response(JSON.stringify({ error: "leaders only" }), { status: 403, headers: { "Content-Type": "application/json", ...cors() } });
      try {
        const body = await request.json();
        if (typeof body.application_key !== "string" || !/^app:\d+:\d+$/.test(body.application_key)) return new Response(JSON.stringify({ error: "invalid application" }), { status: 400, headers: { "Content-Type": "application/json", ...cors() } });
        const raw = await env.APPLICATIONS.get(body.application_key);
        if (!raw) return new Response(JSON.stringify({ error: "application not found" }), { status: 404, headers: { "Content-Type": "application/json", ...cors() } });
        const application = JSON.parse(raw);
        if (application.status !== "declined") return new Response(JSON.stringify({ error: "application is not declined" }), { status: 409, headers: { "Content-Type": "application/json", ...cors() } });
        if (!application.discussion || !application.discussion.summary || !LEADER_IDS.has(String(application.discussion.leader_id))) return new Response(JSON.stringify({ error: "applicant must submit a discussion summary and select a leader before review" }), { status: 409, headers: { "Content-Type": "application/json", ...cors() } });
        application.status = "pending";
        application.review_history = Array.isArray(application.review_history) ? application.review_history : [];
        application.review_history.push({ leader_id: charId, leader_name: LEADER_NAMES[charId], reviewed_at: new Date().toISOString() });
        application.reviewed_at = application.review_history[application.review_history.length - 1].reviewed_at;
        application.reviewed_by = charId;
        application.reviewed_by_name = LEADER_NAMES[charId];
        await env.APPLICATIONS.put(body.application_key, JSON.stringify(application));
        return new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json", ...cors() } });
      } catch {
        return new Response(JSON.stringify({ error: "could not reopen application" }), { status: 400, headers: { "Content-Type": "application/json", ...cors() } });
      }
    }

    if (url.pathname === "/corp-officers/remove" && request.method === "POST") {
      const viewerId = await charIdFromToken(tokenFrom(request));
      if (!viewerId || !LEADER_IDS.has(viewerId)) return Response.json({ error: "leaders only" }, { status: 403 });
      try {
        const body = await request.json();
        const characterId = String(body.character_id || "");
        if (!/^[0-9]+$/.test(characterId)) return Response.json({ error: "Invalid character ID" }, { status: 400 });
        if (LEADER_IDS.has(characterId)) return Response.json({ error: "Cannot remove a configured recruitment leader" }, { status: 403 });
        const keys = [];
        let cursor;
        do {
          const page = await env.APPLICATIONS.list({ prefix: "app:" + characterId + ":", cursor });
          keys.push(...page.keys.map(item => item.name));
          cursor = page.list_complete ? undefined : page.cursor;
        } while (cursor);
        if (!keys.length) return Response.json({ error: "No registered application found" }, { status: 404 });
        await Promise.all(keys.map(key => env.APPLICATIONS.delete(key)));
        return Response.json({ ok: true, removed_applications: keys.length });
      } catch (error) {
        return Response.json({ error: String(error) }, { status: 500 });
      }
    }

    if (url.pathname === "/corp-officers" && request.method === "GET") {
      const viewerId = await charIdFromToken(tokenFrom(request));
      if (!viewerId || !LEADER_IDS.has(viewerId)) {
        return Response.json({ error: "leaders only" }, { status: 403 });
      }
      try {
        const leaderResponse = await fetch("https://esi.evetech.net/latest/characters/1655394838/?datasource=tranquility");
        if (!leaderResponse.ok) throw new Error("Could not retrieve datalost's corporation");
        const leader = await leaderResponse.json();
        const corporationId = leader.corporation_id;
        const corporationResponse = await fetch("https://esi.evetech.net/latest/corporations/" + corporationId + "/?datasource=tranquility");
        const corporation = corporationResponse.ok ? await corporationResponse.json() : {};
        const records = [];
        let cursor;
        do {
          const page = await env.APPLICATIONS.list({ prefix: "app:", cursor });
          const batch = await Promise.all(page.keys.map(async entry => {
            const raw = await env.APPLICATIONS.get(entry.name);
            if (!raw) return null;
            try { return JSON.parse(raw); } catch { return null; }
          }));
          records.push(...batch.filter(Boolean));
          cursor = page.list_complete ? undefined : page.cursor;
        } while (cursor);
        const latest = new Map();
        for (const record of records) {
          const id = String(record.character_id || "");
          const previous = latest.get(id);
          if (id && (!previous || (record.submitted_at || "") > (previous.submitted_at || ""))) latest.set(id, record);
        }
        const checked = await Promise.all([...latest.values()].map(async record => {
          const id = Number(record.character_id);
          if (!Number.isSafeInteger(id) || id <= 0) return null;
          try {
            const response = await fetch("https://esi.evetech.net/latest/characters/" + id + "/?datasource=tranquility");
            if (!response.ok) return null;
            const character = await response.json();
            return {
              character_id: id,
              name: character.name || record.name || String(id),
              corporation_id: character.corporation_id,
              status: record.status || "pending"
            };
          } catch { return null; }
        }));
        const users = checked.filter(Boolean);
        return Response.json({
          corporation_id: corporationId,
          corporation_name: corporation.name || String(corporationId),
          members: users.filter(user => user.status === "accepted" && user.corporation_id === corporationId),
          awaiting_transfer: users.filter(user => user.status === "accepted" && user.corporation_id !== corporationId),
          tracked_only: true
        }, { headers: { "Cache-Control": "no-store" } });
      } catch (error) {
        return Response.json({ error: String(error) }, { status: 502 });
      }
    }

    if (url.pathname === "/applications" && request.method === "GET") {
      const charId = await charIdFromToken(tokenFrom(request));
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
        if (val) apps.push({ ...JSON.parse(val), application_key: k.name });
      }
      const latest = new Map();
      for (const a of apps) {
        const id = String(a.character_id || "");
        const prev = latest.get(id);
        if (!prev || (a.submitted_at || "") > (prev.submitted_at || "")) latest.set(id, a);
      }
      const requestedStatus = url.searchParams.get("status") === "declined" ? "declined" : "pending";
      const unique = [...latest.values()].filter(a => (a.status || "pending") === requestedStatus).sort((a, b) => (b.submitted_at || "").localeCompare(a.submitted_at || ""));
      return new Response(JSON.stringify(unique), {
        headers: { "Content-Type": "application/json", ...cors() },
      });
    }

    if (url.pathname === "/callback") {
      return env.ASSETS.fetch(new Request(new URL("/", url), request));
    }

    return env.ASSETS.fetch(request);
  },
};
