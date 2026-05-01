// v2: tightened JWT + cookie + CSRF surface.
// Kept some of the runtime/protocol vulns in server.py so the compare diff
// still shows meaningful overlap with v1.

const jwt = require("jsonwebtoken");
const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(cookieParser());

// MCP-230 FIX: real signature verification with a fixed algorithm.
function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_KEY, { algorithms: ["RS256"] });
}

// MCP-231 FIX: every issued token carries an explicit expiry.
function issueToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    process.env.JWT_KEY,
    { algorithm: "RS256", expiresIn: "1h" },
  );
}

// MCP-234 FIX: server sets an HttpOnly Secure SameSite=Strict cookie. No
// localStorage / sessionStorage involvement.
function persistSession(res, token) {
  res.cookie("__Host-session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    path: "/",
  });
}

// MCP-235 FIX: lightweight CSRF middleware checks `X-CSRF-Token` header
// against a cookie value on every state-changing route.
function csrfProtection(req, res, next) {
  const header = req.get("X-CSRF-Token");
  const cookie = req.cookies["__Host-csrf"];
  if (!header || !cookie || !crypto.timingSafeEqual(Buffer.from(header), Buffer.from(cookie))) {
    return res.status(403).json({ error: "csrf" });
  }
  return next();
}

app.post("/upload", csrfProtection, async (req, res) => {
  const userId = req.cookies["__Host-session"];
  await upload(userId, req.body.path, req.body.content);
  res.json({ ok: true });
});

app.delete("/file", csrfProtection, async (req, res) => {
  const userId = req.cookies["__Host-session"];
  await deleteFile(userId, req.body.path);
  res.json({ ok: true });
});

app.put("/file", csrfProtection, async (req, res) => {
  const userId = req.cookies["__Host-session"];
  await rename(userId, req.body.from, req.body.to);
  res.json({ ok: true });
});

async function upload(_a, _b, _c) {}
async function deleteFile(_a, _b) {}
async function rename(_a, _b, _c) {}

module.exports = { verifyToken, issueToken, persistSession, app };
