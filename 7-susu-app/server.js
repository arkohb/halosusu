/* =====================================================================
   HaloSusu — group rotating-savings (susu / ajo) platform
   ---------------------------------------------------------------------
   Roles:
     • super admin  — controls the site; approves/verifies group admins
     • group admin  — self-registers, gets approved, buys a tier, creates
                      groups, adds members, runs the rotation
     • member       — added strictly by a group admin; pays contributions
                      via MoMo or card (no login; uses a private pay link)

   Money model (READ THE COMPLIANCE NOTE IN SUSU-SETUP.txt):
     This server tracks contributions as a LEDGER and automates collection
     through Paystack. "Locked" = collected & held; "released" = counted
     into a payout. Actually holding a float and disbursing other people's
     money is a regulated activity — pair this with a licensed payment
     partner before going live with real funds.

   Stack: Node 22+ (built-in node:sqlite), no external deps. Paystack for
   MoMo/card. Same auth style as the order-server (scrypt + HMAC tokens).
   ===================================================================== */

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const AUTH_SECRET = process.env.AUTH_SECRET || "change-me-susu-secret";
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "";
const PAYSTACK_PUBLIC_KEY = process.env.PAYSTACK_PUBLIC_KEY || "";
const CURRENCY = process.env.CURRENCY || "GHS";

/* notifications (all optional — log-fallback when unset) */
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";        // email, resend.com
const MAIL_FROM = process.env.MAIL_FROM || "onboarding@resend.dev";
const ARKESEL_API_KEY = process.env.ARKESEL_API_KEY || "";      // SMS, arkesel.com (Ghana)
const SMS_SENDER = (process.env.SMS_SENDER || "HaloSusu").slice(0, 11);

/* ===================== security hardening ===================== */
const NODE_ENV = process.env.NODE_ENV || "development";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
const MAX_BODY = 512 * 1024; // cap request bodies at 512 KB (anti-DoS)
const CSP = [
  "default-src 'self'", "base-uri 'self'", "object-src 'none'", "frame-ancestors 'self'", "form-action 'self'",
  "img-src 'self' data: https:",
  "script-src 'self' 'unsafe-inline' https://js.paystack.co https://paystack.com https://*.paystack.com https://*.paystack.co",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://paystack.com https://*.paystack.com",
  "font-src 'self' https://fonts.gstatic.com https://paystack.com https://*.paystack.com",
  "connect-src 'self' https://api.paystack.co https://paystack.com https://*.paystack.com https://*.paystack.co",
  "frame-src https://paystack.com https://*.paystack.com https://*.paystack.co",
].join("; ");

if (NODE_ENV === "production" && (AUTH_SECRET === "change-me-susu-secret" || AUTH_SECRET.length < 16)) {
  console.error("FATAL: set a strong AUTH_SECRET (16+ random chars) before running in production.");
  process.exit(1);
}

function clientIp(req) {
  return (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket?.remoteAddress || "unknown";
}
const _rl = new Map();
function rateLimit(req, bucket, max, windowMs) {
  const key = clientIp(req) + "|" + bucket, now = Date.now();
  let e = _rl.get(key);
  if (!e || now > e.reset) { e = { count: 0, reset: now + windowMs }; _rl.set(key, e); }
  e.count++; return e.count <= max;
}
setInterval(() => { const now = Date.now(); for (const [k, e] of _rl) if (now > e.reset) _rl.delete(k); }, 60000).unref();
function safeEqual(a, b) {
  const ab = Buffer.from(String(a)), bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}
function securityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "geolocation=(self), camera=(), microphone=()");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Content-Security-Policy", CSP);
}
function applyCors(req, res) {
  const origin = req.headers.origin; // same-origin requests need no CORS; only allowlisted cross-origin gets a header
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "authorization,content-type");
  }
}
/* ============================================================== */
const APP_URL = process.env.APP_URL || "";                       // e.g. https://halosusu.up.railway.app

/* ---------- storage ---------- */
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || process.env.DATA_DIR || __dirname;
const db = new DatabaseSync(path.join(DATA_DIR, "susu.db"));
db.exec(`
CREATE TABLE IF NOT EXISTS admins(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT NOT NULL DEFAULT 'group',          -- 'super' | 'group'
  name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT,
  pass_hash TEXT NOT NULL, salt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',       -- 'pending'|'active'|'suspended'
  tier_id INTEGER, groups_allowed INTEGER DEFAULT 0, members_per_group INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS tiers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, price_minor INTEGER NOT NULL DEFAULT 0,
  max_groups INTEGER NOT NULL, max_members INTEGER NOT NULL,
  blurb TEXT, active INTEGER DEFAULT 1, sort INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tier_payments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL, tier_id INTEGER NOT NULL,
  reference TEXT UNIQUE NOT NULL, amount_minor INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending', created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS groups(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER NOT NULL, name TEXT NOT NULL,
  contribution_minor INTEGER NOT NULL, frequency TEXT NOT NULL DEFAULT 'monthly',
  rotation TEXT NOT NULL DEFAULT 'join_order', -- 'join_order'|'random'
  status TEXT NOT NULL DEFAULT 'draft',          -- 'draft'|'active'|'completed'
  current_cycle INTEGER DEFAULT 0, num_cycles INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')), started_at TEXT
);
CREATE TABLE IF NOT EXISTS members(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL, name TEXT NOT NULL, phone TEXT,
  pay_token TEXT UNIQUE NOT NULL, position INTEGER,
  authorization_code TEXT, email TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS cycles(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL, idx INTEGER NOT NULL,
  recipient_member_id INTEGER, pot_minor INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',         -- 'pending'|'funded'|'paid_out'
  due_date TEXT, paid_out_at TEXT
);
CREATE TABLE IF NOT EXISTS contributions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL, cycle_id INTEGER NOT NULL, member_id INTEGER NOT NULL,
  amount_minor INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'due',             -- 'due'|'locked'|'released'|'defaulted'
  reference TEXT, locked_at TEXT, created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS payouts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id INTEGER NOT NULL, cycle_id INTEGER NOT NULL, recipient_member_id INTEGER NOT NULL,
  amount_minor INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'released',
  released_at TEXT DEFAULT (datetime('now'))
);
`);

/* ---------- lightweight migrations (add columns if missing) ---------- */
function ensureColumn(table, col, def) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
  if (!cols.includes(col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`);
}
ensureColumn("members", "recipient_code", "TEXT");      // Paystack transfer recipient
ensureColumn("members", "payout_provider", "TEXT");     // MoMo provider / bank code
ensureColumn("members", "payout_account", "TEXT");      // phone or account number
ensureColumn("members", "payout_name", "TEXT");
ensureColumn("payouts", "transfer_reference", "TEXT");
ensureColumn("payouts", "transfer_code", "TEXT");
ensureColumn("payouts", "transfer_status", "TEXT DEFAULT 'pending'"); // pending|no_method|success|otp_required|failed|reversed

/* ---------- seed tiers + super admin ---------- */
if (!db.prepare("SELECT COUNT(*) n FROM tiers").get().n) {
  const ins = db.prepare("INSERT INTO tiers(name,price_minor,max_groups,max_members,blurb,sort) VALUES (?,?,?,?,?,?)");
  ins.run("Starter", 0,       1,  10, "Try one small group", 1);
  ins.run("Growth",  10000,   5,  30, "Run several groups",  2);   // GHS 100
  ins.run("Pro",     30000,  20, 100, "For serious organisers", 3); // GHS 300
  console.log("Seeded default tiers.");
}
(function seedSuper() {
  const exists = db.prepare("SELECT id FROM admins WHERE role='super' LIMIT 1").get();
  if (exists) return;
  const email = (process.env.SUPER_ADMIN_EMAIL || "super@halosusu.app").toLowerCase();
  const pass = process.env.SUPER_ADMIN_PASSWORD || crypto.randomBytes(6).toString("hex");
  const salt = crypto.randomBytes(16).toString("hex");
  db.prepare(`INSERT INTO admins(role,name,email,phone,pass_hash,salt,status,groups_allowed,members_per_group)
              VALUES ('super','Super Admin',?,?,?,?,'active',999999,999999)`)
    .run(email, "", hashPassword(pass, salt), salt);
  console.log("==================================================");
  console.log(" SUPER ADMIN created:");
  console.log("   email:    " + email);
  console.log("   password: " + pass);
  console.log(" (set SUPER_ADMIN_EMAIL / SUPER_ADMIN_PASSWORD env to control this)");
  console.log("==================================================");
})();

/* ---------- helpers ---------- */
function hashPassword(pw, salt) { return crypto.scryptSync(String(pw), salt, 64).toString("hex"); }
function checkPassword(pw, hash, salt) {
  const a = Buffer.from(hashPassword(pw, salt), "hex");
  const b = Buffer.from(hash, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function signToken(admin) {
  const payload = Buffer.from(JSON.stringify({ id: admin.id, role: admin.role, exp: Date.now() + 30 * 86400000 })).toString("base64url");
  const sig = crypto.createHmac("sha256", AUTH_SECRET).update(payload).digest("base64url");
  return payload + "." + sig;
}
function adminFromToken(token) {
  if (!token) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return null;
  const expected = crypto.createHmac("sha256", AUTH_SECRET).update(payload).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  let data; try { data = JSON.parse(Buffer.from(payload, "base64url").toString()); } catch { return null; }
  if (data.exp && Date.now() > data.exp) return null;
  const a = db.prepare("SELECT * FROM admins WHERE id=?").get(data.id);
  return a || null;
}
function bearer(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? adminFromToken(h.slice(7)) : null;
}
function readBody(req) {
  return new Promise((resolve) => {
    let d = "", len = 0, done = false;
    req.on("data", (c) => { if (done) return; len += c.length; if (len > MAX_BODY) { done = true; try { req.destroy(); } catch {} return resolve(""); } d += c; });
    req.on("end", () => { if (!done) resolve(d); });
    req.on("error", () => { if (!done) { done = true; resolve(""); } });
  });
}
function json(res, code, obj) {
  if (res.writableEnded || res.destroyed) return;
  try { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); } catch {}
}
function baseUrl(req) {
  return APP_URL || ((req.headers["x-forwarded-proto"] || "http") + "://" + (req.headers.host || ""));
}
const money = (m) => (CURRENCY === "GHS" ? "₵" : CURRENCY + " ") + (Number(m || 0) / 100).toLocaleString();
const ref = (prefix) => prefix + "-" + crypto.randomBytes(5).toString("hex").toUpperCase();
function rotateMs(freq) {
  return freq === "weekly" ? 7 : freq === "biweekly" ? 14 : 30;  // days
}

/* ---------- Paystack ---------- */
async function paystack(method, endpoint, body) {
  const r = await fetch("https://api.paystack.co" + endpoint, {
    method,
    headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json();
  return data;
}
async function verifyPaystack(reference) {
  const data = await paystack("GET", "/transaction/verify/" + encodeURIComponent(reference));
  if (!data.status) throw new Error(data.message || "verify failed");
  return data.data; // {status, amount, currency, authorization, customer, ...}
}

/* ---------- Paystack Transfers (disbursement to recipients) ---------- */
async function listPayoutBanks() {
  // MoMo providers for Ghana, banks for Nigeria.
  const qs = CURRENCY === "GHS" ? "currency=GHS&type=mobile_money" : "currency=" + CURRENCY;
  const data = await paystack("GET", "/bank?" + qs);
  return (data.data || []).map((b) => ({ name: b.name, code: b.code }));
}
async function createTransferRecipient({ name, account, provider }) {
  const type = CURRENCY === "GHS" ? "mobile_money" : "nuban";
  const data = await paystack("POST", "/transferrecipient", {
    type, name, account_number: account, bank_code: provider, currency: CURRENCY,
  });
  if (!data.status) throw new Error(data.message || "could not create recipient");
  return data.data.recipient_code;
}
async function initiateTransfer({ amount_minor, recipient_code, reason, reference }) {
  const data = await paystack("POST", "/transfer", {
    source: "balance", amount: amount_minor, recipient: recipient_code,
    currency: CURRENCY, reason: reason || "Susu payout", reference,
  });
  return data; // {status, message, data:{transfer_code, status:'success'|'pending'|'otp'|...}}
}
/* Attempt the actual money-out for a recorded payout. Returns a status string. */
async function attemptTransfer(payoutId) {
  const payout = db.prepare("SELECT * FROM payouts WHERE id=?").get(payoutId);
  if (!payout) return { transfer_status: "failed", message: "payout not found" };
  const m = db.prepare("SELECT * FROM members WHERE id=?").get(payout.recipient_member_id);
  if (!m) return { transfer_status: "failed", message: "recipient not found" };

  // need a transfer recipient_code; build one from saved payout details if absent
  let recipientCode = m.recipient_code;
  if (!recipientCode) {
    if (!m.payout_provider || !m.payout_account) {
      db.prepare("UPDATE payouts SET transfer_status='no_method' WHERE id=?").run(payoutId);
      return { transfer_status: "no_method", message: `${m.name} has no payout method set` };
    }
    try {
      recipientCode = await createTransferRecipient({
        name: m.payout_name || m.name, account: m.payout_account, provider: m.payout_provider });
      db.prepare("UPDATE members SET recipient_code=? WHERE id=?").run(recipientCode, m.id);
    } catch (e) {
      db.prepare("UPDATE payouts SET transfer_status='failed' WHERE id=?").run(payoutId);
      return { transfer_status: "failed", message: e.message };
    }
  }

  const reference = payout.transfer_reference || ref("TRF");
  db.prepare("UPDATE payouts SET transfer_reference=? WHERE id=?").run(reference, payoutId);
  let resp;
  try {
    resp = await initiateTransfer({ amount_minor: payout.amount_minor, recipient_code: recipientCode,
      reason: "Susu payout", reference });
  } catch (e) {
    db.prepare("UPDATE payouts SET transfer_status='failed' WHERE id=?").run(payoutId);
    return { transfer_status: "failed", message: e.message };
  }
  const ps = resp?.data?.status;
  const status = !resp.status ? "failed"
    : ps === "success" ? "success"
    : ps === "otp" ? "otp_required"
    : ps === "pending" || ps === "queued" || ps === "processing" ? "pending"
    : "failed";
  db.prepare("UPDATE payouts SET transfer_status=?, transfer_code=? WHERE id=?")
    .run(status, resp?.data?.transfer_code || null, payoutId);
  const msg = status === "success" ? "Transfer sent"
    : status === "pending" ? "Transfer queued — Paystack is processing it"
    : status === "otp_required" ? "Paystack needs an OTP — disable Transfers OTP in your Paystack settings to automate payouts"
    : "Transfer failed: " + (resp.message || "unknown");
  return { transfer_status: status, message: msg };
}

/* =====================================================================
   Notifications (email via Resend, SMS via Arkesel) — best effort
   ===================================================================== */
function normalizePhoneGh(raw) {
  let d = String(raw || "").replace(/[^\d]/g, "");
  if (!d) return "";
  if (d.startsWith("00")) d = d.slice(2);
  if (d.startsWith("0")) d = "233" + d.slice(1);
  else if (d.length === 9) d = "233" + d;        // e.g. 24XXXXXXX
  return d;
}
async function sendEmail(to, subject, html) {
  if (!to) return false;
  if (!RESEND_API_KEY) { console.log(`📨 (no RESEND_API_KEY) email -> ${to}: ${subject}`); return false; }
  try {
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: MAIL_FROM, to: [to], subject, html }),
    });
    if (!r.ok) console.error(`email -> ${to} failed (${r.status})`);
    return r.ok;
  } catch (e) { console.error("email error", e.message); return false; }
}
async function sendSMS(to, text) {
  const phone = normalizePhoneGh(to);
  if (!phone) return false;
  if (!ARKESEL_API_KEY) { console.log(`📱 (no ARKESEL_API_KEY) SMS -> ${phone}: ${text}`); return false; }
  try {
    const r = await fetch("https://sms.arkesel.com/api/v2/sms/send", {
      method: "POST",
      headers: { "api-key": ARKESEL_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ sender: SMS_SENDER, message: text, recipients: [phone] }),
    });
    if (!r.ok) console.error(`SMS -> ${phone} failed (${r.status})`);
    return r.ok;
  } catch (e) { console.error("SMS error", e.message); return false; }
}
function notifyMember(member, subject, smsText, emailHtml) {
  if (member.phone) sendSMS(member.phone, smsText).catch(() => {});
  if (member.email) sendEmail(member.email, subject, emailHtml).catch(() => {});
}
const emailWrap = (title, body) =>
  `<div style="font-family:sans-serif;max-width:460px;margin:auto">
     <div style="background:#171410;color:#e0a92b;padding:14px 18px;border-radius:12px 12px 0 0;font-weight:bold;font-size:18px">HaloSusu</div>
     <div style="border:1px solid #e2d6bd;border-top:none;border-radius:0 0 12px 12px;padding:18px">
       <h2 style="margin:.2em 0">${title}</h2>${body}</div></div>`;

/* notify everyone with a still-due contribution in the group's current cycle */
function notifyCycleDue(groupId, base) {
  const g = db.prepare("SELECT * FROM groups WHERE id=?").get(groupId);
  if (!g || g.status !== "active") return;
  const cycle = db.prepare("SELECT * FROM cycles WHERE group_id=? AND idx=?").get(groupId, g.current_cycle);
  if (!cycle) return;
  const recip = db.prepare("SELECT name FROM members WHERE id=?").get(cycle.recipient_member_id);
  const due = db.prepare(`SELECT m.* FROM contributions c JOIN members m ON m.id=c.member_id
    WHERE c.cycle_id=? AND c.status IN ('due','defaulted')`).all(cycle.id);
  const amt = money(g.contribution_minor);
  for (const m of due) {
    const link = (base || APP_URL) ? `${base || APP_URL}/pay?t=${m.pay_token}` : "";
    const sms = `HaloSusu: ${g.name} turn ${cycle.idx}/${g.num_cycles}. Your ${amt} contribution is due (${recip?.name || ""} receives this turn).` + (link ? ` Pay: ${link}` : "");
    const html = emailWrap(`Contribution due — ${g.name}`,
      `<p>Turn <b>${cycle.idx} of ${g.num_cycles}</b>. Your contribution of <b>${amt}</b> is due.</p>
       <p>${recip?.name || "A member"} receives the pot this turn.</p>
       ${link ? `<p><a href="${link}" style="background:#d99b16;color:#171410;padding:10px 16px;border-radius:8px;text-decoration:none;font-weight:bold">Pay your contribution</a></p>` : ""}`);
    notifyMember(m, `Contribution due — ${g.name}`, sms, html);
  }
}
/* notify the recipient that their turn was paid out */
function notifyPayout(payoutId, base) {
  const p = db.prepare("SELECT * FROM payouts WHERE id=?").get(payoutId);
  if (!p) return;
  const m = db.prepare("SELECT * FROM members WHERE id=?").get(p.recipient_member_id);
  const g = db.prepare("SELECT * FROM groups WHERE id=?").get(p.group_id);
  if (!m || !g) return;
  const amt = money(p.amount_minor);
  const sms = `HaloSusu: It's your turn! ${amt} from ${g.name} is being sent to you.`;
  const html = emailWrap(`Your turn — ${g.name}`,
    `<p>Congratulations ${m.name}! You're the recipient this turn.</p>
     <p style="font-size:24px;font-weight:bold">${amt}</p>
     <p>is being transferred to your payout method.</p>`);
  notifyMember(m, `Your susu payout — ${g.name}`, sms, html);
}
function startGroup(group) {
  let members = db.prepare("SELECT * FROM members WHERE group_id=? ORDER BY id ASC").all(group.id);
  if (members.length < 2) throw new Error("need at least 2 members to start");
  if (group.rotation === "random") {
    for (let i = members.length - 1; i > 0; i--) {
      const j = crypto.randomInt(i + 1);
      [members[i], members[j]] = [members[j], members[i]];
    }
  }
  const setPos = db.prepare("UPDATE members SET position=? WHERE id=?");
  members.forEach((m, i) => setPos.run(i + 1, m.id));

  const N = members.length;
  const pot = group.contribution_minor * N;
  const days = rotateMs(group.frequency);
  const insCycle = db.prepare(`INSERT INTO cycles(group_id,idx,recipient_member_id,pot_minor,due_date)
                               VALUES (?,?,?,?,?)`);
  for (let i = 0; i < N; i++) {
    const due = new Date(Date.now() + days * (i + 1) * 86400000).toISOString().slice(0, 10);
    insCycle.run(group.id, i + 1, members[i].id, pot, due);
  }
  db.prepare("UPDATE groups SET status='active', current_cycle=1, num_cycles=?, started_at=datetime('now') WHERE id=?")
    .run(N, group.id);
  generateContributions(group.id, 1);
  return N;
}
function generateContributions(groupId, cycleIdx) {
  const group = db.prepare("SELECT * FROM groups WHERE id=?").get(groupId);
  const cycle = db.prepare("SELECT * FROM cycles WHERE group_id=? AND idx=?").get(groupId, cycleIdx);
  if (!cycle) return;
  const exists = db.prepare("SELECT COUNT(*) n FROM contributions WHERE cycle_id=?").get(cycle.id).n;
  if (exists) return;
  const members = db.prepare("SELECT * FROM members WHERE group_id=?").all(groupId);
  const ins = db.prepare(`INSERT INTO contributions(group_id,cycle_id,member_id,amount_minor) VALUES (?,?,?,?)`);
  for (const m of members) ins.run(groupId, cycle.id, m.id, group.contribution_minor);
}
function cycleFunded(cycleId) {
  const outstanding = db.prepare("SELECT COUNT(*) n FROM contributions WHERE cycle_id=? AND status NOT IN ('locked','released')").get(cycleId).n;
  return outstanding === 0;
}
function payoutCurrentCycle(group) {
  const cycle = db.prepare("SELECT * FROM cycles WHERE group_id=? AND idx=?").get(group.id, group.current_cycle);
  if (!cycle) throw new Error("no active cycle");
  if (cycle.status === "paid_out") throw new Error("this turn was already paid out");
  if (!cycleFunded(cycle.id)) {
    const left = db.prepare("SELECT COUNT(*) n FROM contributions WHERE cycle_id=? AND status NOT IN ('locked','released')").get(cycle.id).n;
    throw new Error(`${left} contribution(s) still unpaid — collect or auto-charge them before paying out`);
  }
  db.prepare("UPDATE contributions SET status='released' WHERE cycle_id=? AND status='locked'").run(cycle.id);
  db.prepare("UPDATE cycles SET status='paid_out', paid_out_at=datetime('now') WHERE id=?").run(cycle.id);
  const pr = db.prepare(`INSERT INTO payouts(group_id,cycle_id,recipient_member_id,amount_minor) VALUES (?,?,?,?)`)
    .run(group.id, cycle.id, cycle.recipient_member_id, cycle.pot_minor);
  const payoutId = pr.lastInsertRowid;

  if (group.current_cycle < group.num_cycles) {
    const next = group.current_cycle + 1;
    db.prepare("UPDATE groups SET current_cycle=? WHERE id=?").run(next, group.id);
    generateContributions(group.id, next);
  } else {
    db.prepare("UPDATE groups SET status='completed' WHERE id=?").run(group.id);
  }
  return { cycle, payoutId };
}

/* full read-model for one group */
function groupDetail(groupId) {
  const g = db.prepare("SELECT * FROM groups WHERE id=?").get(groupId);
  if (!g) return null;
  const members = db.prepare("SELECT id,name,phone,pay_token,position,(authorization_code IS NOT NULL) AS auto_charge,(recipient_code IS NOT NULL OR (payout_provider IS NOT NULL AND payout_account IS NOT NULL)) AS payout_ready,payout_provider,payout_account FROM members WHERE group_id=? ORDER BY COALESCE(position,id)").all(groupId);
  const cycles = db.prepare("SELECT * FROM cycles WHERE group_id=? ORDER BY idx").all(groupId);
  const contributions = db.prepare("SELECT * FROM contributions WHERE group_id=?").all(groupId);
  const payouts = db.prepare("SELECT * FROM payouts WHERE group_id=? ORDER BY id").all(groupId);
  const nameById = Object.fromEntries(members.map((m) => [m.id, m.name]));
  const enrichedCycles = cycles.map((c) => {
    const cc = contributions.filter((x) => x.cycle_id === c.id);
    return {
      ...c, recipient_name: nameById[c.recipient_member_id] || "—",
      locked: cc.filter((x) => x.status === "locked" || x.status === "released").length,
      total: cc.length,
      due_members: cc.filter((x) => x.status === "due" || x.status === "defaulted")
                     .map((x) => ({ member_id: x.member_id, name: nameById[x.member_id], status: x.status })),
    };
  });
  return { group: g, members, cycles: enrichedCycles,
    payouts: payouts.map((p) => ({ ...p, recipient_name: nameById[p.recipient_member_id] || "—" })),
    money_fmt: true };
}

/* apply a successful payment to its target (contribution or tier) */
async function applyPayment(reference, paystackData) {
  const paidAmount = Number(paystackData?.amount || 0);
  const paidCurrency = paystackData?.currency || CURRENCY;

  // contribution?
  const contrib = db.prepare("SELECT * FROM contributions WHERE reference=?").get(reference);
  if (contrib) {
    if (contrib.status !== "locked" && contrib.status !== "released") {
      // never trust the client for money — the charge must cover what's owed
      if (paidCurrency !== CURRENCY || paidAmount < contrib.amount_minor) {
        console.warn(`! underpaid contribution ${reference}: got ${paidAmount} ${paidCurrency}, need ${contrib.amount_minor} ${CURRENCY}`);
        return { kind: "contribution", id: contrib.id, ok: false, reason: "amount_mismatch" };
      }
      db.prepare("UPDATE contributions SET status='locked', locked_at=datetime('now') WHERE id=?").run(contrib.id);
    }
    const auth = paystackData?.authorization?.authorization_code;
    if (auth) db.prepare("UPDATE members SET authorization_code=?, email=COALESCE(email,?) WHERE id=?")
      .run(auth, paystackData?.customer?.email || null, contrib.member_id);
    return { kind: "contribution", id: contrib.id, ok: true };
  }
  // tier subscription?
  const tp = db.prepare("SELECT * FROM tier_payments WHERE reference=?").get(reference);
  if (tp) {
    if (tp.status !== "paid") {
      if (paidCurrency !== CURRENCY || paidAmount < tp.amount_minor) {
        console.warn(`! underpaid tier ${reference}: got ${paidAmount}, need ${tp.amount_minor}`);
        return { kind: "tier", id: tp.id, ok: false, reason: "amount_mismatch" };
      }
      db.prepare("UPDATE tier_payments SET status='paid' WHERE id=?").run(tp.id);
      const tier = db.prepare("SELECT * FROM tiers WHERE id=?").get(tp.tier_id);
      db.prepare("UPDATE admins SET tier_id=?, groups_allowed=?, members_per_group=? WHERE id=?")
        .run(tier.id, tier.max_groups, tier.max_members, tp.admin_id);
    }
    return { kind: "tier", id: tp.id, ok: true };
  }
  return { kind: "unknown", ok: false };
}

/* =====================================================================
   HTTP server
   ===================================================================== */
const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript",
  ".png": "image/png", ".svg": "image/svg+xml", ".webmanifest": "application/manifest+json", ".ico": "image/x-icon" };
const PAGES = { "/": "index.html", "/super": "super.html", "/admin": "admin.html", "/pay": "pay.html" };

function serveStatic(res, pathname) {
  let rel = PAGES[pathname] || pathname.replace(/^\/+/, "");
  const full = path.join(__dirname, "public", rel);
  if (!full.startsWith(path.join(__dirname, "public"))) { res.writeHead(403); return res.end("forbidden"); }
  fs.readFile(full, (err, buf) => {
    if (err) { res.writeHead(404, { "Content-Type": "text/html" }); return res.end("<h1>404</h1>"); }
    res.writeHead(200, { "Content-Type": MIME[path.extname(full)] || "application/octet-stream" });
    res.end(buf);
  });
}

const server = http.createServer(async (req, res) => {
  securityHeaders(res);
  applyCors(req, res);
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  // throttle auth + payment endpoints per IP (brute-force / abuse guard)
  if (/login|signup/.test(p) && req.method === "POST") {
    if (!rateLimit(req, "auth", 12, 5 * 60 * 1000)) return json(res, 429, { error: "Too many attempts. Please wait a few minutes and try again." });
  } else if (p.startsWith("/api/pay")) {
    if (!rateLimit(req, "pay", 40, 5 * 60 * 1000)) return json(res, 429, { error: "Too many requests, please slow down." });
  }

  try {
    /* ---- health + config ---- */
    if (p === "/health") return json(res, 200, { ok: true, time: new Date().toISOString() });
    if (p === "/api/config") return json(res, 200, { publicKey: PAYSTACK_PUBLIC_KEY, currency: CURRENCY });

    /* ---- public: tiers list ---- */
    if (req.method === "GET" && p === "/api/tiers") {
      const tiers = db.prepare("SELECT id,name,price_minor,max_groups,max_members,blurb FROM tiers WHERE active=1 ORDER BY sort").all();
      return json(res, 200, { tiers });
    }

    /* ---- auth ---- */
    if (req.method === "POST" && p === "/api/admin/signup") {
      const b = JSON.parse((await readBody(req)) || "{}");
      const name = String(b.name || "").trim(), email = String(b.email || "").trim().toLowerCase();
      const phone = String(b.phone || "").trim(), password = String(b.password || "");
      if (!name || !email || !password) return json(res, 400, { error: "name, email and password are required" });
      if (password.length < 6) return json(res, 400, { error: "password must be at least 6 characters" });
      if (db.prepare("SELECT id FROM admins WHERE email=?").get(email)) return json(res, 409, { error: "that email is already registered" });
      const salt = crypto.randomBytes(16).toString("hex");
      db.prepare(`INSERT INTO admins(role,name,email,phone,pass_hash,salt,status) VALUES ('group',?,?,?,?,?,'pending')`)
        .run(name, email, phone, hashPassword(password, salt), salt);
      return json(res, 200, { ok: true, message: "Registration received. A super admin must approve your account before you can sign in." });
    }

    if (req.method === "POST" && p === "/api/admin/login") {
      const b = JSON.parse((await readBody(req)) || "{}");
      const email = String(b.email || "").trim().toLowerCase();
      const a = db.prepare("SELECT * FROM admins WHERE email=?").get(email);
      if (!a || !checkPassword(String(b.password || ""), a.pass_hash, a.salt)) return json(res, 401, { error: "wrong email or password" });
      if (a.status === "suspended") return json(res, 403, { error: "your account is suspended" });
      return json(res, 200, {
        token: signToken(a), role: a.role, status: a.status, name: a.name,
        groups_allowed: a.groups_allowed, members_per_group: a.members_per_group,
        pending: a.status === "pending",
      });
    }

    if (req.method === "GET" && p === "/api/me") {
      const a = bearer(req); if (!a) return json(res, 401, { error: "unauthorized" });
      const tier = a.tier_id ? db.prepare("SELECT name FROM tiers WHERE id=?").get(a.tier_id) : null;
      return json(res, 200, { id: a.id, role: a.role, name: a.name, email: a.email, status: a.status,
        tier: tier?.name || null, groups_allowed: a.groups_allowed, members_per_group: a.members_per_group });
    }

    /* =================== SUPER ADMIN =================== */
    if (p.startsWith("/api/super/")) {
      const a = bearer(req);
      if (!a || a.role !== "super") return json(res, 403, { error: "super admin only" });

      if (req.method === "GET" && p === "/api/super/overview") {
        const counts = {
          pending: db.prepare("SELECT COUNT(*) n FROM admins WHERE role='group' AND status='pending'").get().n,
          active_admins: db.prepare("SELECT COUNT(*) n FROM admins WHERE role='group' AND status='active'").get().n,
          groups: db.prepare("SELECT COUNT(*) n FROM groups").get().n,
          members: db.prepare("SELECT COUNT(*) n FROM members").get().n,
          locked_minor: db.prepare("SELECT COALESCE(SUM(amount_minor),0) s FROM contributions WHERE status='locked'").get().s,
          paid_out_minor: db.prepare("SELECT COALESCE(SUM(amount_minor),0) s FROM payouts").get().s,
        };
        const admins = db.prepare(`SELECT a.id,a.name,a.email,a.phone,a.status,a.created_at,t.name tier,
            (SELECT COUNT(*) FROM groups g WHERE g.admin_id=a.id) groups
          FROM admins a LEFT JOIN tiers t ON t.id=a.tier_id
          WHERE a.role='group' ORDER BY a.created_at DESC`).all();
        return json(res, 200, { counts, admins });
      }

      const mApprove = p.match(/^\/api\/super\/admins\/(\d+)\/(approve|reject|suspend|unsuspend)$/);
      if (req.method === "POST" && mApprove) {
        const id = Number(mApprove[1]), action = mApprove[2];
        const target = db.prepare("SELECT * FROM admins WHERE id=? AND role='group'").get(id);
        if (!target) return json(res, 404, { error: "admin not found" });
        const status = action === "approve" || action === "unsuspend" ? "active"
                     : action === "suspend" ? "suspended" : "rejected";
        if (action === "reject") db.prepare("DELETE FROM admins WHERE id=?").run(id);
        else db.prepare("UPDATE admins SET status=? WHERE id=?").run(status, id);
        return json(res, 200, { ok: true, status });
      }

      if (req.method === "POST" && p === "/api/super/tiers") {
        const b = JSON.parse((await readBody(req)) || "{}");
        const id = Number(b.id), mg = Math.max(1, Number(b.max_groups) || 1), mm = Math.max(1, Number(b.max_members) || 1);
        if (!id) return json(res, 400, { error: "missing tier id" });
        db.prepare("UPDATE tiers SET price_minor=?, max_groups=?, max_members=?, blurb=? WHERE id=?")
          .run(Math.round(Number(b.price || 0) * 100), mg, mm, String(b.blurb || ""), id);
        // apply the new limits to everyone already on this plan
        db.prepare("UPDATE admins SET groups_allowed=?, members_per_group=? WHERE tier_id=?").run(mg, mm, id);
        return json(res, 200, { ok: true });
      }
    }

    /* =================== GROUP ADMIN =================== */
    function requireActiveGroupAdmin() {
      const a = bearer(req);
      if (!a || a.role !== "group") { json(res, 403, { error: "group admin only" }); return null; }
      if (a.status !== "active") { json(res, 403, { error: "your account is awaiting super-admin approval" }); return null; }
      return a;
    }

    if (req.method === "POST" && p === "/api/tiers/subscribe") {
      const a = requireActiveGroupAdmin(); if (!a) return;
      const b = JSON.parse((await readBody(req)) || "{}");
      const tier = db.prepare("SELECT * FROM tiers WHERE id=? AND active=1").get(Number(b.tier_id));
      if (!tier) return json(res, 404, { error: "tier not found" });
      if (tier.price_minor === 0) {
        db.prepare("UPDATE admins SET tier_id=?, groups_allowed=?, members_per_group=? WHERE id=?")
          .run(tier.id, tier.max_groups, tier.max_members, a.id);
        return json(res, 200, { free: true, ok: true });
      }
      const reference = ref("SUB");
      db.prepare("INSERT INTO tier_payments(admin_id,tier_id,reference,amount_minor) VALUES (?,?,?,?)")
        .run(a.id, tier.id, reference, tier.price_minor);
      return json(res, 200, { reference, amount_minor: tier.price_minor, email: a.email, publicKey: PAYSTACK_PUBLIC_KEY });
    }

    if (req.method === "GET" && p === "/api/groups") {
      const a = requireActiveGroupAdmin(); if (!a) return;
      const groups = db.prepare(`SELECT g.*,
          (SELECT COUNT(*) FROM members m WHERE m.group_id=g.id) members
        FROM groups g WHERE g.admin_id=? ORDER BY g.created_at DESC`).all(a.id);
      const used = db.prepare("SELECT COUNT(*) n FROM groups WHERE admin_id=? AND status!='completed'").get(a.id).n;
      return json(res, 200, { groups, limits: { groups_allowed: a.groups_allowed, members_per_group: a.members_per_group, groups_used: used } });
    }

    if (req.method === "POST" && p === "/api/groups") {
      const a = requireActiveGroupAdmin(); if (!a) return;
      const b = JSON.parse((await readBody(req)) || "{}");
      const have = db.prepare("SELECT COUNT(*) n FROM groups WHERE admin_id=? AND status!='completed'").get(a.id).n;
      if (have >= a.groups_allowed) return json(res, 403, { error: `your tier allows ${a.groups_allowed} active group(s). Complete or delete one, or upgrade.` });
      const name = String(b.name || "").trim();
      const contribution = Math.round(Number(b.contribution || 0) * 100);
      const frequency = ["weekly", "biweekly", "monthly"].includes(b.frequency) ? b.frequency : "monthly";
      const rotation = b.rotation === "random" ? "random" : "join_order";
      if (!name || contribution <= 0) return json(res, 400, { error: "group name and a contribution amount are required" });
      const r = db.prepare("INSERT INTO groups(admin_id,name,contribution_minor,frequency,rotation) VALUES (?,?,?,?,?)")
        .run(a.id, name, contribution, frequency, rotation);
      return json(res, 200, { ok: true, id: r.lastInsertRowid });
    }

    if (req.method === "GET" && p === "/api/momo-providers") {
      const a = requireActiveGroupAdmin(); if (!a) return;
      try { return json(res, 200, { providers: await listPayoutBanks() }); }
      catch (e) { return json(res, 502, { error: e.message }); }
    }

    const mPayMethod = p.match(/^\/api\/groups\/(\d+)\/members\/(\d+)\/payout-method$/);
    if (req.method === "POST" && mPayMethod) {
      const a = requireActiveGroupAdmin(); if (!a) return;
      const gid = Number(mPayMethod[1]), mid = Number(mPayMethod[2]);
      const g = db.prepare("SELECT * FROM groups WHERE id=? AND admin_id=?").get(gid, a.id);
      if (!g) return json(res, 404, { error: "group not found" });
      const m = db.prepare("SELECT * FROM members WHERE id=? AND group_id=?").get(mid, gid);
      if (!m) return json(res, 404, { error: "member not found" });
      const b = JSON.parse((await readBody(req)) || "{}");
      const provider = String(b.provider || "").trim();
      const account = String(b.account || "").trim();
      const name = String(b.name || m.name).trim();
      if (!provider || !account) return json(res, 400, { error: "provider and account number are required" });
      let recipientCode;
      try { recipientCode = await createTransferRecipient({ name, account, provider }); }
      catch (e) { return json(res, 502, { error: "Paystack rejected these details: " + e.message }); }
      db.prepare("UPDATE members SET payout_provider=?, payout_account=?, payout_name=?, recipient_code=? WHERE id=?")
        .run(provider, account, name, recipientCode, mid);
      return json(res, 200, { ok: true });
    }

    const mTransfer = p.match(/^\/api\/groups\/(\d+)\/payouts\/(\d+)\/transfer$/);
    if (req.method === "POST" && mTransfer) {
      const a = requireActiveGroupAdmin(); if (!a) return;
      const gid = Number(mTransfer[1]), pid = Number(mTransfer[2]);
      const g = db.prepare("SELECT * FROM groups WHERE id=? AND admin_id=?").get(gid, a.id);
      if (!g) return json(res, 404, { error: "group not found" });
      const payout = db.prepare("SELECT * FROM payouts WHERE id=? AND group_id=?").get(pid, gid);
      if (!payout) return json(res, 404, { error: "payout not found" });
      const tr = await attemptTransfer(pid);
      return json(res, 200, { ok: true, ...tr });
    }

    const mGroup = p.match(/^\/api\/groups\/(\d+)(\/[a-z]+)?(\/\d+)?$/);
    if (mGroup) {
      const a = requireActiveGroupAdmin(); if (!a) return;
      const gid = Number(mGroup[1]);
      const g = db.prepare("SELECT * FROM groups WHERE id=? AND admin_id=?").get(gid, a.id);
      if (!g) return json(res, 404, { error: "group not found" });
      const sub = mGroup[2];

      if (req.method === "GET" && !sub) return json(res, 200, groupDetail(gid));

      if (req.method === "DELETE" && !sub) {
        if (g.status !== "draft") return json(res, 400, { error: "only a group that hasn't started can be deleted" });
        db.prepare("DELETE FROM members WHERE group_id=?").run(gid);
        db.prepare("DELETE FROM groups WHERE id=?").run(gid);
        return json(res, 200, { ok: true });
      }

      if (req.method === "POST" && sub === "/members") {
        if (g.status !== "draft") return json(res, 400, { error: "members can only be added before the group starts" });
        const have = db.prepare("SELECT COUNT(*) n FROM members WHERE group_id=?").get(gid).n;
        if (have >= a.members_per_group) return json(res, 403, { error: `your tier allows ${a.members_per_group} members per group.` });
        const b = JSON.parse((await readBody(req)) || "{}");
        const name = String(b.name || "").trim();
        if (!name) return json(res, 400, { error: "member name is required" });
        const token = crypto.randomBytes(9).toString("base64url");
        db.prepare("INSERT INTO members(group_id,name,phone,pay_token,email) VALUES (?,?,?,?,?)")
          .run(gid, name, String(b.phone || "").trim(), token, String(b.email || "").trim() || null);
        const base = baseUrl(req);
        const link = base ? `${base}/pay?t=${token}` : "";
        notifyMember({ phone: String(b.phone || "").trim(), email: String(b.email || "").trim() || null },
          `You've been added to ${g.name}`,
          `HaloSusu: ${a.name} added you to "${g.name}". You'll contribute ${money(g.contribution_minor)} each turn.` + (link ? ` Your link: ${link}` : ""),
          emailWrap(`You're in ${g.name}`,
            `<p>${a.name} added you to the susu "<b>${g.name}</b>".</p>
             <p>Contribution: <b>${money(g.contribution_minor)}</b> per turn.</p>
             ${link ? `<p><a href="${link}" style="background:#d99b16;color:#171410;padding:10px 16px;border-radius:8px;text-decoration:none;font-weight:bold">Open your pay page</a></p>` : ""}`));
        return json(res, 200, { ok: true, pay_token: token });
      }

      if (req.method === "DELETE" && sub === "/members" && mGroup[3]) {
        if (g.status !== "draft") return json(res, 400, { error: "cannot remove members after the group starts" });
        db.prepare("DELETE FROM members WHERE id=? AND group_id=?").run(Number(mGroup[3].slice(1)), gid);
        return json(res, 200, { ok: true });
      }

      if (req.method === "POST" && sub === "/start") {
        if (g.status !== "draft") return json(res, 400, { error: "group already started" });
        const n = startGroup(g);
        notifyCycleDue(gid, baseUrl(req));
        return json(res, 200, { ok: true, cycles: n });
      }

      if (req.method === "POST" && sub === "/collect") {
        // Anti-default: auto-charge every still-due member in the current cycle
        // who has a saved Paystack authorization (from a prior payment).
        const cycle = db.prepare("SELECT * FROM cycles WHERE group_id=? AND idx=?").get(gid, g.current_cycle);
        if (!cycle) return json(res, 400, { error: "no active cycle" });
        const due = db.prepare(`SELECT c.*, m.authorization_code, m.email, m.name FROM contributions c
          JOIN members m ON m.id=c.member_id
          WHERE c.cycle_id=? AND c.status IN ('due','defaulted')`).all(cycle.id);
        let charged = 0, failed = 0, skipped = 0;
        for (const c of due) {
          if (!c.authorization_code || !c.email) { skipped++; continue; }
          const reference = ref("SU");
          db.prepare("UPDATE contributions SET reference=? WHERE id=?").run(reference, c.id);
          const r = await paystack("POST", "/transaction/charge_authorization", {
            authorization_code: c.authorization_code, email: c.email,
            amount: c.amount_minor, currency: CURRENCY, reference,
          });
          if (r.status && r.data?.status === "success") {
            db.prepare("UPDATE contributions SET status='locked', locked_at=datetime('now') WHERE id=?").run(c.id);
            charged++;
          } else {
            db.prepare("UPDATE contributions SET status='defaulted' WHERE id=?").run(c.id);
            failed++;
          }
        }
        return json(res, 200, { ok: true, charged, failed, skipped,
          message: `Auto-charged ${charged}, failed ${failed}, skipped ${skipped} (no saved payment method).` });
      }

      if (req.method === "POST" && sub === "/payout") {
        const { cycle, payoutId } = payoutCurrentCycle(g);
        const tr = await attemptTransfer(payoutId);
        const base = baseUrl(req);
        notifyPayout(payoutId, base);
        const fresh = db.prepare("SELECT status FROM groups WHERE id=?").get(gid);
        if (fresh.status === "active") notifyCycleDue(gid, base);
        return json(res, 200, { ok: true, paid_cycle: cycle.idx, payout_id: payoutId,
          transfer_status: tr.transfer_status, message: tr.message });
      }
    }

    /* =================== MEMBER (public, by pay token) =================== */
    const mMember = p.match(/^\/api\/member\/([^/]+)(\/[a-z-]+)?$/);
    if (mMember) {
      const token = mMember[1], sub = mMember[2];
      const member = db.prepare("SELECT * FROM members WHERE pay_token=?").get(token);
      if (!member) return json(res, 404, { error: "invalid link" });
      const g = db.prepare("SELECT * FROM groups WHERE id=?").get(member.group_id);

      if (req.method === "GET" && !sub) {
        let dueContrib = null, cycleInfo = null, you = null;
        if (g.status === "active" || g.status === "completed") {
          const myCycle = db.prepare("SELECT idx,due_date,status FROM cycles WHERE group_id=? AND recipient_member_id=?").get(g.id, member.id);
          if (myCycle) you = { position: member.position, turn: myCycle.idx, of: g.num_cycles,
            due_date: myCycle.due_date, received: myCycle.status === "paid_out" };
        }
        if (g.status === "active") {
          const cycle = db.prepare("SELECT * FROM cycles WHERE group_id=? AND idx=?").get(g.id, g.current_cycle);
          if (cycle) {
            dueContrib = db.prepare("SELECT * FROM contributions WHERE cycle_id=? AND member_id=?").get(cycle.id, member.id);
            const recip = db.prepare("SELECT name FROM members WHERE id=?").get(cycle.recipient_member_id);
            cycleInfo = { idx: cycle.idx, of: g.num_cycles, recipient: recip?.name, due_date: cycle.due_date };
          }
        }
        return json(res, 200, {
          member: { name: member.name }, group: { name: g.name, status: g.status, contribution_minor: g.contribution_minor },
          cycle: cycleInfo, you,
          due: dueContrib ? { id: dueContrib.id, status: dueContrib.status, amount_minor: dueContrib.amount_minor } : null,
          publicKey: PAYSTACK_PUBLIC_KEY, currency: CURRENCY, email: member.email || "",
        });
      }

      if (req.method === "POST" && sub === "/pay-init") {
        if (g.status !== "active") return json(res, 400, { error: "this group is not collecting right now" });
        const cycle = db.prepare("SELECT * FROM cycles WHERE group_id=? AND idx=?").get(g.id, g.current_cycle);
        const c = db.prepare("SELECT * FROM contributions WHERE cycle_id=? AND member_id=?").get(cycle.id, member.id);
        if (!c) return json(res, 400, { error: "nothing due" });
        if (c.status === "locked" || c.status === "released") return json(res, 400, { error: "this turn is already paid" });
        const b = JSON.parse((await readBody(req)) || "{}");
        const email = String(b.email || member.email || "").trim();
        if (email && !member.email) db.prepare("UPDATE members SET email=? WHERE id=?").run(email, member.id);
        const reference = c.reference || ref("SU");
        if (!c.reference) db.prepare("UPDATE contributions SET reference=? WHERE id=?").run(reference, c.id);
        return json(res, 200, { reference, amount_minor: c.amount_minor, email, publicKey: PAYSTACK_PUBLIC_KEY, currency: CURRENCY });
      }
    }

    /* =================== payment verify (any reference) =================== */
    if (req.method === "POST" && p === "/api/pay/verify") {
      const b = JSON.parse((await readBody(req)) || "{}");
      const reference = String(b.reference || "");
      if (!reference) return json(res, 400, { error: "missing reference" });
      try {
        const data = await verifyPaystack(reference);
        if (data.status !== "success") return json(res, 400, { error: "payment not successful", status: data.status });
        const result = await applyPayment(reference, data);
        if (result.ok === false && result.reason === "amount_mismatch")
          return json(res, 400, { error: "the amount paid doesn't match what's owed — please contact your group admin" });
        return json(res, 200, { ok: true, ...result });
      } catch (e) {
        return json(res, 502, { error: "could not verify with Paystack: " + e.message });
      }
    }

    /* =================== Paystack webhook =================== */
    if (req.method === "POST" && p === "/paystack/webhook") {
      const raw = await readBody(req);
      const sig = req.headers["x-paystack-signature"];
      const expected = crypto.createHmac("sha512", PAYSTACK_SECRET_KEY).update(raw).digest("hex");
      if (!safeEqual(sig || "", expected)) return json(res, 401, { error: "bad signature" });
      const evt = JSON.parse(raw || "{}");
      if (evt.event === "charge.success") {
        await applyPayment(evt.data.reference, evt.data).catch(() => {});
      } else if (evt.event && evt.event.startsWith("transfer.")) {
        const reference = evt.data?.reference;
        const st = { "transfer.success": "success", "transfer.failed": "failed", "transfer.reversed": "reversed" }[evt.event];
        if (reference && st) db.prepare("UPDATE payouts SET transfer_status=? WHERE transfer_reference=?").run(st, reference);
      }
      return json(res, 200, { received: true });
    }

    /* ---- static files / pages ---- */
    if (req.method === "GET") return serveStatic(res, p);
    return json(res, 404, { error: "not found" });
  } catch (e) {
    console.error("ERR", p, e);
    return json(res, 500, { error: e.message || "server error" });
  }
});

server.listen(PORT, () => console.log(`HaloSusu server on :${PORT}  (data: ${DATA_DIR})`));
