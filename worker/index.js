const SERVICES = new Set(["freight", "project", "warehouse", "agency", "other"]);
const STATUSES = new Set(["new", "handling", "done"]);
const PBKDF2_ITERATIONS = 100000;

function text(value, max) {
  return String(value == null ? "" : value).trim().slice(0, max);
}

function json(status, body, extra) {
  const headers = Object.assign({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store"
  }, extra || {});
  return new Response(JSON.stringify(body), { status, headers });
}

function redirect(location) {
  return new Response(null, { status: 302, headers: { location, "cache-control": "no-store" } });
}

function cookies(request) {
  const out = {};
  String(request.headers.get("cookie") || "").split(";").forEach((part) => {
    const index = part.indexOf("=");
    if (index > 0) out[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  });
  return out;
}

function same(left, right) {
  const a = String(left);
  const b = String(right);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return diff === 0;
}

function randomHex(size) {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    hash: "SHA-256",
    salt: hexToBytes(saltHex),
    iterations: PBKDF2_ITERATIONS
  }, key, 256);
  return [...new Uint8Array(bits)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function collectEnquiry(body, requireTerms) {
  const fields = [];
  const firstName = text(body.first_name, 80);
  const lastName = text(body.last_name, 80);
  const company = text(body.company, 160);
  const email = text(body.email, 160);
  const phone = text(body.phone, 40);
  const country = text(body.country, 80);
  const message = text(body.message, 4000);
  const services = Array.isArray(body.services) ? body.services.filter((item) => SERVICES.has(item)) : [];
  if (!firstName) fields.push("first_name");
  if (!lastName) fields.push("last_name");
  if (!company) fields.push("company");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fields.push("email");
  if (!phone) fields.push("phone");
  if (requireTerms && body.terms !== true) fields.push("terms");
  return { fields, firstName, lastName, company, email, phone, country, services, message };
}

function itemFrom(row) {
  let services = [];
  try { services = JSON.parse(row.services || "[]"); } catch (error) { services = []; }
  return {
    id: row.id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    locale: row.locale,
    firstName: row.first_name,
    lastName: row.last_name,
    company: row.company,
    email: row.email,
    phone: row.phone,
    country: row.country,
    services,
    message: row.message,
    status: row.status,
    note: row.note
  };
}

async function readJson(request, limit) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > limit) return { error: 413 };
  const raw = await request.text();
  if (raw.length > limit) return { error: 413 };
  try { return { body: JSON.parse(raw || "{}") }; } catch (error) { return { body: null }; }
}

async function sessionUser(db, request) {
  const token = cookies(request).ng_admin;
  if (!token) return null;
  const now = Date.now();
  const row = await db.prepare("SELECT username, expires_at FROM sessions WHERE token = ?").bind(token).first();
  if (!row || row.expires_at < now) {
    await db.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return null;
  }
  return row.username;
}

async function limited(db, ip) {
  const now = Date.now();
  const windowStart = now - 10 * 60 * 1000;
  await db.prepare("DELETE FROM rate_hits WHERE at < ?").bind(windowStart).run();
  const count = await db.prepare("SELECT COUNT(*) AS total FROM rate_hits WHERE ip = ? AND at >= ?").bind(ip, windowStart).first();
  await db.prepare("INSERT INTO rate_hits (ip, at) VALUES (?, ?)").bind(ip, now).run();
  return Number(count && count.total) >= 8;
}

function cookie(token, maxAge, secure) {
  return "ng_admin=" + (token || "") + "; HttpOnly; SameSite=Lax; Path=/; Max-Age=" + maxAge + (secure ? "; Secure" : "");
}

async function insertEnquiry(db, body, collected) {
  const now = new Date().toISOString();
  const record = {
    id: randomHex(8),
    createdAt: now,
    updatedAt: now,
    locale: text(body.locale, 12) || "en",
    status: STATUSES.has(body.status) ? body.status : "new",
    note: text(body.note, 2000),
    ...collected,
    services: collected.services
  };
  await db.prepare(
    "INSERT INTO enquiries (id, created_at, updated_at, locale, first_name, last_name, company, email, phone, country, services, message, status, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    record.id, record.createdAt, record.updatedAt, record.locale,
    record.firstName, record.lastName, record.company, record.email, record.phone,
    record.country, JSON.stringify(record.services), record.message, record.status, record.note
  ).run();
  return {
    id: record.id,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    locale: record.locale,
    firstName: record.firstName,
    lastName: record.lastName,
    company: record.company,
    email: record.email,
    phone: record.phone,
    country: record.country,
    services: record.services,
    message: record.message,
    status: record.status,
    note: record.note
  };
}

async function handleApi(request, env, url) {
  const db = env.DB;
  const secure = url.protocol === "https:";
  const pathname = url.pathname;

  if (request.method === "POST" && pathname === "/api/enquiries") {
    const ip = request.headers.get("cf-connecting-ip") || "local";
    if (await limited(db, ip)) return json(429, { ok: false, error: "rate" });
    const parsed = await readJson(request, 20000);
    if (parsed.error) return json(parsed.error, { ok: false, error: "invalid", fields: [] });
    if (!parsed.body) return json(400, { ok: false, error: "invalid", fields: [] });
    if (text(parsed.body.company_website, 200)) return json(200, { ok: true });
    const collected = collectEnquiry(parsed.body, true);
    if (collected.fields.length) return json(400, { ok: false, error: "invalid", fields: collected.fields });
    await insertEnquiry(db, parsed.body, collected);
    return json(200, { ok: true });
  }

  if (request.method === "POST" && pathname === "/api/admin/login") {
    const parsed = await readJson(request, 4000);
    const body = parsed.body || {};
    const username = text(body.username, 40);
    const password = String(body.password || "");
    const admin = await db.prepare("SELECT username, salt, password_hash FROM admins WHERE username = ?").bind(username).first();
    const hash = admin ? await hashPassword(password, admin.salt) : "";
    if (!admin || !same(hash, admin.password_hash)) return json(401, { ok: false, error: "login" });
    const token = randomHex(24);
    const expires = Date.now() + 12 * 60 * 60 * 1000;
    await db.prepare("INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)").bind(token, admin.username, expires).run();
    return json(200, { ok: true }, { "set-cookie": cookie(token, 43200, secure) });
  }

  if (request.method === "POST" && pathname === "/api/admin/logout") {
    const token = cookies(request).ng_admin;
    if (token) await db.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return json(200, { ok: true }, { "set-cookie": cookie("", 0, secure) });
  }

  if (pathname.startsWith("/api/admin/")) {
    if (!await sessionUser(db, request)) return json(401, { ok: false, error: "auth" });
    if (request.method === "GET" && pathname === "/api/admin/enquiries") {
      const result = await db.prepare("SELECT * FROM enquiries ORDER BY created_at DESC").all();
      return json(200, { ok: true, items: (result.results || []).map(itemFrom) });
    }
    if (request.method === "POST" && pathname === "/api/admin/enquiries") {
      const parsed = await readJson(request, 20000);
      if (parsed.error) return json(parsed.error, { ok: false, error: "invalid", fields: [] });
      if (!parsed.body) return json(400, { ok: false, error: "invalid", fields: [] });
      const collected = collectEnquiry(parsed.body, false);
      if (collected.fields.length) return json(400, { ok: false, error: "invalid", fields: collected.fields });
      const item = await insertEnquiry(db, parsed.body, collected);
      return json(200, { ok: true, item });
    }
    const match = pathname.match(/^\/api\/admin\/enquiries\/([a-f0-9]{16})$/);
    if (!match) return json(404, { ok: false });
    const current = await db.prepare("SELECT * FROM enquiries WHERE id = ?").bind(match[1]).first();
    if (!current) return json(404, { ok: false });
    if (request.method === "DELETE") {
      await db.prepare("DELETE FROM enquiries WHERE id = ?").bind(match[1]).run();
      return json(200, { ok: true });
    }
    if (request.method === "PATCH") {
      const parsed = await readJson(request, 20000);
      if (parsed.error) return json(parsed.error, { ok: false, error: "invalid", fields: [] });
      if (!parsed.body) return json(400, { ok: false, error: "invalid", fields: [] });
      const collected = collectEnquiry(parsed.body, false);
      if (collected.fields.length) return json(400, { ok: false, error: "invalid", fields: collected.fields });
      if (parsed.body.status && !STATUSES.has(parsed.body.status)) return json(400, { ok: false, error: "status" });
      const status = parsed.body.status && STATUSES.has(parsed.body.status) ? parsed.body.status : current.status;
      const note = typeof parsed.body.note === "string" ? text(parsed.body.note, 2000) : current.note;
      const locale = parsed.body.locale ? text(parsed.body.locale, 12) : current.locale;
      const updatedAt = new Date().toISOString();
      await db.prepare(
        "UPDATE enquiries SET updated_at = ?, locale = ?, first_name = ?, last_name = ?, company = ?, email = ?, phone = ?, country = ?, services = ?, message = ?, status = ?, note = ? WHERE id = ?"
      ).bind(
        updatedAt, locale, collected.firstName, collected.lastName, collected.company, collected.email,
        collected.phone, collected.country, JSON.stringify(collected.services), collected.message, status, note, match[1]
      ).run();
      const saved = await db.prepare("SELECT * FROM enquiries WHERE id = ?").bind(match[1]).first();
      return json(200, { ok: true, item: itemFrom(saved) });
    }
    return json(405, { ok: false });
  }

  return null;
}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const pathname = url.pathname;
      if (pathname === "/data" || pathname.startsWith("/data/")) return new Response("Not found", { status: 404 });
      if (pathname.startsWith("/api/")) {
        const response = await handleApi(request, env, url);
        return response || json(404, { ok: false });
      }
      const user = await sessionUser(env.DB, request);
      if (pathname === "/admin/login" || pathname === "/admin/login/") {
        if (user) return redirect("/admin/");
        return env.ASSETS.fetch(request);
      }
      if (pathname === "/admin" || pathname === "/admin/" || pathname === "/admin/index.html") {
        if (!user) return redirect("/admin/login");
        return env.ASSETS.fetch(request);
      }
      if (request.method !== "GET" && request.method !== "HEAD") return new Response("Method not allowed", { status: 405 });
      return env.ASSETS.fetch(request);
    } catch (error) {
      return json(500, { ok: false, error: "server" });
    }
  }
};
