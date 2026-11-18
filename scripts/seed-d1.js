const { execFileSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");

const root = path.join(__dirname, "..");
const passwordFile = path.join(root, "data", "admin-password.txt");
const enquiriesFile = path.join(root, "data", "enquiries.json");

function sqlString(value) {
  return "'" + String(value == null ? "" : value).replace(/'/g, "''") + "'";
}

const passwordText = fs.readFileSync(passwordFile, "utf8");
const password = (passwordText.match(/password:\s*(.+)/) || [])[1];
if (!password) throw new Error("data/admin-password.txt has no password");
const salt = crypto.randomBytes(16).toString("hex");
const hash = crypto.pbkdf2Sync(password.trim(), Buffer.from(salt, "hex"), 100000, 32, "sha256").toString("hex");

const statements = [
  "INSERT OR REPLACE INTO admins (username, salt, password_hash) VALUES (" +
    [sqlString("admin"), sqlString(salt), sqlString(hash)].join(", ") + ");"
];

if (fs.existsSync(enquiriesFile)) {
  const items = JSON.parse(fs.readFileSync(enquiriesFile, "utf8"));
  items.forEach((item) => {
    statements.push(
      "INSERT OR REPLACE INTO enquiries (id, created_at, updated_at, locale, first_name, last_name, company, email, phone, country, services, message, status, note) VALUES (" +
      [
        item.id, item.createdAt, item.updatedAt, item.locale || "en", item.firstName, item.lastName,
        item.company, item.email, item.phone, item.country || "", JSON.stringify(item.services || []),
        item.message || "", item.status || "new", item.note || ""
      ].map(sqlString).join(", ") + ");"
    );
  });
}

const file = path.join(os.tmpdir(), "northgo-d1-seed.sql");
fs.writeFileSync(file, statements.join("\n") + "\n");
try {
  execFileSync("npx", ["wrangler", "d1", "execute", "northgo", "--remote", "--file", file, "--yes"], {
    cwd: root,
    stdio: "inherit",
    shell: true
  });
} finally {
  fs.rmSync(file, { force: true });
}
console.log("Seeded D1 admin and " + (statements.length - 1) + " enquiries.");
