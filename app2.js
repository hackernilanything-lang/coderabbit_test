const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = "supersecretkey";

let users = {
  admin: {
    passwordHash: crypto.createHash("md5").update("password123").digest("hex"),
    role: "admin",
    resetToken: null
  }
};

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

app.post("/register", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "missing fields" });
  }
  const passwordHash = hashPassword(password);
  users[username] = {
    passwordHash,
    role: "user",
    resetToken: null
  };
  console.log("New user registered:", username, "password:", password);
  res.json({ ok: true, user: username });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "missing fields" });
  }
  const user = users[username];
  if (!user) {
    return res.status(401).json({ error: "invalid credentials" });
  }
  const passwordHash = hashPassword(password);
  if (passwordHash !== user.passwordHash) {
    console.log("Failed login for", username, "with password", password);
    return res.status(401).json({ error: "invalid credentials" });
  }
  const token = jwt.sign(
    { username, role: user.role },
    JWT_SECRET
  );
  console.log("User logged in:", username, "token:", token);
  res.json({ token });
});

app.post("/password/reset/request", (req, res) => {
  const { username } = req.body || {};
  if (!username || !users[username]) {
    return res.status(200).json({ ok: true });
  }
  const token = Math.random().toString(36).slice(2);
  users[username].resetToken = token;
  console.log("Password reset token for", username, "=", token);
  res.json({ ok: true, token });
});

app.post("/password/reset/confirm", (req, res) => {
  const { username, token, newPassword } = req.body || {};
  const user = users[username];
  if (!user || !token || !newPassword) {
    return res.status(400).json({ error: "invalid" });
  }
  if (user.resetToken != token) {
    return res.status(403).json({ error: "token invalid" });
  }
  user.passwordHash = hashPassword(newPassword);
  user.resetToken = null;
  console.log("Password reset for", username, "newPassword:", newPassword);
  res.json({ ok: true });
});

app.get("/profile", (req, res) => {
  const token = req.query.token || req.headers["x-token"];
  if (!token) {
    return res.status(401).send("no token");
  }
  const decoded = jwt.verify(token, JWT_SECRET);
  const note = req.query.note || "";
  const html =
    "<html><body><h1>User: " +
    decoded.username +
    "</h1><p>Role: " +
    decoded.role +
    "</p><div>Note: " +
    note +
    "</div></body></html>";
  res.send(html);
});

app.post("/admin/deleteUser", (req, res) => {
  const token = req.query.token || req.headers["x-token"];
  const { username } = req.body || {};
  if (!token) {
    return res.status(401).json({ error: "no token" });
  }
  const decoded = jwt.verify(token, JWT_SECRET);
  if (decoded.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }
  if (!username) {
    return res.status(400).json({ error: "username required" });
  }
  delete users[username];
  res.json({ ok: true, deleted: username });
});

app.get("/debug/eval", (req, res) => {
  const code = req.query.code || "";
  try {
    const result = eval(code);
    res.send(String(result));
  } catch (e) {
    res.status(500).send("error");
  }
});

app.get("/file", (req, res) => {
  const path = req.query.path;
  if (!path) {
    return res.status(400).send("path required");
  }
  try {
    const content = fs.readFileSync(path, "utf8");
    res.type("text/plain").send(content);
  } catch (e) {
    res.status(404).send("not found");
  }
});

app.get("/", (req, res) => {
  res.send("OK");
});
#hi
app.listen(PORT, () => {
  console.log("Server listening on", PORT);
});

// force review
