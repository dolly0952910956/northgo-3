const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const PORT = Number(process.env.PORT) || 8766;
const DATA = path.join(ROOT, "data");
const ENQUIRIES_FILE = path.join(DATA, "enquiries.json");
const ADMIN_FILE = path.join(DATA, "admin.json");
const PASSWORD_FILE = path.join(DATA, "admin-password.txt");
const SERVICES = new Set(["freight", "project", "warehouse", "agency", "other"]);
const STATUSES = new Set(["new", "handling", "done"]);
const sessions = new Map();
const hits = new Map();

function ensureStore() {
  fs.mkdirSync(DATA, { recursive: true });
  if (!fs.existsSync(ENQUIRIES_FILE)) fs.writeFileSync(ENQUIRIES_FILE, "[]\n");
  if (!fs.existsSync(ADMIN_FILE)) {
    const password = "Ng-" + crypto.randomBytes(6).toString("base64url");
    const salt = crypto.randomBytes(16).toString("hex");
    const record = { username: "admin", salt, passwordHash: hashPassword(password, salt) };
    fs.writeFileSync(ADMIN_FILE, JSON.stringify(record, null, 2));
    fs.writeFileSync(PASSWORD_FILE, "username: admin\npassword: " + password + "\n");
    console.log("Admin login created. Username: admin");
    console.log("Password: " + password);
  }
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 32).toString("hex");
}

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    return fallback;
  }
}

function writeJson(file, value) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2) + "\n");
  fs.renameSync(tmp, file);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(Object.assign(new Error("too large"), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function parseJson(text) {
  try {
    return JSON.parse(text || "{}");
  } catch (error) {
    return null;
  }
}

function cookies(req) {
  const out = {};
  String(req.headers.cookie || "").split(";").forEach((part) => {
    const index = part.indexOf("=");
    if (index > 0) out[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
  });
  return out;
}

function sessionUser(req) {
  const token = cookies(req).ng_admin;
  const session = token && sessions.get(token);
  if (!session || session.expires < Date.now()) {
    if (token) sessions.delete(token);
    return null;
  }
  return session.username;
}

function text(value, max) {
  return String(value == null ? "" : value).trim().slice(0, max);
}

function clientIp(req) {
  return req.socket.remoteAddress || "local";
}

function limited(ip) {
  const now = Date.now();
  const recent = (hits.get(ip) || []).filter((time) => now - time < 10 * 60 * 1000);
  recent.push(now);
  hits.set(ip, recent);
  return recent.length > 8;
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

function newEnquiry(body, collected) {
  const now = new Date().toISOString();
  return {
    id: crypto.randomBytes(8).toString("hex"),
    createdAt: now,
    updatedAt: now,
    locale: text(body.locale, 12) || "en",
    firstName: collected.firstName,
    lastName: collected.lastName,
    company: collected.company,
    email: collected.email,
    phone: collected.phone,
    country: collected.country,
    services: collected.services,
    message: collected.message,
    status: STATUSES.has(body.status) ? body.status : "new",
    note: text(body.note, 2000)
  };
}

function send(res, status, body, extra) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  const headers = Object.assign({
    "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(payload)
  }, extra || {});
  res.writeHead(status, headers);
  res.end(payload);
}

function safePath(urlPath) {
  let decoded = urlPath;
  try {
    decoded = decodeURIComponent(urlPath);
  } catch (error) {
    return null;
  }
  if (decoded.includes("\0")) return null;
  const full = path.normalize(path.join(ROOT, decoded.replace(/^\/+/, "")));
  const relative = path.relative(ROOT, full);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return null;
  if (relative.split(path.sep)[0].toLowerCase() === "data") return null;
  return full;
}

const types = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".xml": "application/xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".ico": "image/x-icon"
};

function serveFile(res, file) {
  fs.readFile(file, (error, bytes) => {
    if (error) {
      send(res, 404, "Not found");
      return;
    }
    res.writeHead(200, {
      "content-type": types[path.extname(file).toLowerCase()] || "application/octet-stream",
      "content-length": bytes.length,
      "cache-control": file.includes(path.sep + "admin" + path.sep) ? "no-store" : "public, max-age=60"
    });
    res.end(bytes);
  });
}

function resolveStatic(urlPath) {
  const clean = urlPath.split("?")[0];
  let file = safePath(clean);
  if (!file) return null;
  if (clean.endsWith("/") || (fs.existsSync(file) && fs.statSync(file).isDirectory())) {
    file = path.join(file, "index.html");
  } else if (!fs.existsSync(file)) {
    const asDir = path.join(file, "index.html");
    if (fs.existsSync(asDir)) file = asDir;
  }
  return fs.existsSync(file) && fs.statSync(file).isFile() ? file : null;
}

async function handle(req, res) {
  const url = new URL(req.url, "http://127.0.0.1");
  const pathname = url.pathname;

  if (req.method === "POST" && pathname === "/api/enquiries") {
    if (limited(clientIp(req))) return send(res, 429, { ok: false, error: "rate" });
    const body = parseJson(await readBody(req, 20000));
    if (!body) return send(res, 400, { ok: false, error: "invalid", fields: [] });
    if (text(body.company_website, 200)) return send(res, 200, { ok: true });
    const collected = collectEnquiry(body, true);
    if (collected.fields.length) return send(res, 400, { ok: false, error: "invalid", fields: collected.fields });
    const list = readJson(ENQUIRIES_FILE, []);
    list.unshift(newEnquiry(body, collected));
    writeJson(ENQUIRIES_FILE, list);
    return send(res, 200, { ok: true });
  }

  if (req.method === "POST" && pathname === "/api/admin/login") {
    const body = parseJson(await readBody(req, 4000)) || {};
    const admin = readJson(ADMIN_FILE, null);
    const username = text(body.username, 40);
    const password = String(body.password || "");
    const hash = admin ? hashPassword(password, admin.salt) : "";
    const match = admin && username === admin.username && crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(admin.passwordHash));
    if (!match) return send(res, 401, { ok: false, error: "login" });
    const token = crypto.randomBytes(24).toString("hex");
    sessions.set(token, { username, expires: Date.now() + 12 * 60 * 60 * 1000 });
    return send(res, 200, { ok: true }, {
      "set-cookie": "ng_admin=" + token + "; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200"
    });
  }

  if (req.method === "POST" && pathname === "/api/admin/logout") {
    const token = cookies(req).ng_admin;
    if (token) sessions.delete(token);
    return send(res, 200, { ok: true }, {
      "set-cookie": "ng_admin=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
    });
  }

  if (pathname.startsWith("/api/admin/")) {
    if (!sessionUser(req)) return send(res, 401, { ok: false, error: "auth" });
    const list = readJson(ENQUIRIES_FILE, []);
    if (req.method === "GET" && pathname === "/api/admin/enquiries") return send(res, 200, { ok: true, items: list });
    if (req.method === "POST" && pathname === "/api/admin/enquiries") {
      const body = parseJson(await readBody(req, 20000));
      if (!body) return send(res, 400, { ok: false, error: "invalid", fields: [] });
      const collected = collectEnquiry(body, false);
      if (collected.fields.length) return send(res, 400, { ok: false, error: "invalid", fields: collected.fields });
      const record = newEnquiry(body, collected);
      list.unshift(record);
      writeJson(ENQUIRIES_FILE, list);
      return send(res, 200, { ok: true, item: record });
    }
    const match = pathname.match(/^\/api\/admin\/enquiries\/([a-f0-9]{16})$/);
    if (!match) return send(res, 404, { ok: false });
    const index = list.findIndex((item) => item.id === match[1]);
    if (index < 0) return send(res, 404, { ok: false });
    if (req.method === "DELETE") {
      list.splice(index, 1);
      writeJson(ENQUIRIES_FILE, list);
      return send(res, 200, { ok: true });
    }
    if (req.method === "PATCH") {
      const body = parseJson(await readBody(req, 20000));
      if (!body) return send(res, 400, { ok: false, error: "invalid", fields: [] });
      const collected = collectEnquiry(body, false);
      if (collected.fields.length) return send(res, 400, { ok: false, error: "invalid", fields: collected.fields });
      if (body.status && !STATUSES.has(body.status)) return send(res, 400, { ok: false, error: "status" });
      list[index].firstName = collected.firstName;
      list[index].lastName = collected.lastName;
      list[index].company = collected.company;
      list[index].email = collected.email;
      list[index].phone = collected.phone;
      list[index].country = collected.country;
      list[index].services = collected.services;
      list[index].message = collected.message;
      if (body.locale) list[index].locale = text(body.locale, 12);
      if (body.status) list[index].status = body.status;
      if (typeof body.note === "string") list[index].note = text(body.note, 2000);
      list[index].updatedAt = new Date().toISOString();
      writeJson(ENQUIRIES_FILE, list);
      return send(res, 200, { ok: true, item: list[index] });
    }
    return send(res, 405, { ok: false });
  }

  if (pathname === "/admin/login" || pathname === "/admin/login/") {
    if (sessionUser(req)) {
      res.writeHead(302, { location: "/admin/" });
      res.end();
      return;
    }
    return serveFile(res, path.join(ROOT, "admin", "login.html"));
  }

  if (pathname === "/admin" || pathname === "/admin/" || pathname === "/admin/index.html") {
    if (!sessionUser(req)) {
      res.writeHead(302, { location: "/admin/login" });
      res.end();
      return;
    }
    return serveFile(res, path.join(ROOT, "admin", "index.html"));
  }

  if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, "Method not allowed");
  const file = resolveStatic(pathname);
  if (!file) return send(res, 404, "Not found");
  return serveFile(res, file);
}

ensureStore();
http.createServer((req, res) => {
  handle(req, res).catch((error) => {
    if (!res.headersSent) send(res, error.status || 500, { ok: false, error: "server" });
  });
}).listen(PORT, "127.0.0.1", () => {
  console.log("Northgo site http://127.0.0.1:" + PORT + "/");
  console.log("Admin http://127.0.0.1:" + PORT + "/admin/");
});
