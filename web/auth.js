// Browser-side helpers for the filesystem dashboard.
// Intentional security issues for MCPSafe e2e testing.

const jwt = require("jsonwebtoken");
const express = require("express");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());

// MCP-230: JWT verification with algorithms: ["none"]
function verifyToken(token) {
  return jwt.verify(token, "secret", { algorithms: ["none"] });
}

// MCP-231: jwt.sign() issued without an expiry claim
function issueToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, email: user.email },
    process.env.JWT_KEY,
  );
}

// MCP-234: auth material stored in localStorage / sessionStorage
function persistSession(token, refresh) {
  localStorage.setItem("token", token);
  localStorage.setItem("auth", token);
  sessionStorage.setItem("api_key", refresh);
}

// MCP-235: state-changing routes with cookie session auth and no CSRF middleware
app.post("/upload", async (req, res) => {
  const userId = req.cookies.session;
  await upload(userId, req.body.path, req.body.content);
  res.json({ ok: true });
});

app.delete("/file", async (req, res) => {
  const userId = req.cookies.session;
  await deleteFile(userId, req.body.path);
  res.json({ ok: true });
});

app.put("/file", async (req, res) => {
  const userId = req.cookies.session;
  await rename(userId, req.body.from, req.body.to);
  res.json({ ok: true });
});

async function upload(_a, _b, _c) {}
async function deleteFile(_a, _b) {}
async function rename(_a, _b, _c) {}

module.exports = { verifyToken, issueToken, persistSession, app };
