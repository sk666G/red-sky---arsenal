// language: JavaScript, file: server.js, target: Red Sky lab — vulnerable node target
// Deliberately vulnerable. Do not deploy this anywhere except the lab.
//   - path traversal on /file?name=
//   - reflected XSS on /search?q=
//   - SQLi-simulated auth on /login
//   - debug endpoint that leaks env on /debug

const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get("/", (req, res) => {
  res.send(`
    <html><body>
    <h1>redsky lab target</h1>
    <form action="/search"><input name="q"><button>search</button></form>
    <form action="/login" method="post">
      <input name="user" placeholder="user">
      <input name="pass" placeholder="pass" type="password">
      <button>login</button>
    </form>
    <a href="/file?name=README.md">read file</a>
    </body></html>
  `);
});

// reflected XSS
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.send(`<html><body><h2>results for: ${q}</h2><p>no results</p></body></html>`);
});

// fake SQLi-style auth (hardcoded but tests the exploit module's detection logic)
app.post("/login", (req, res) => {
  const { user, pass } = req.body || {};
  // deliberately naive — the classic ' OR '1'='1 bypass
  if ((user === "admin" && pass === "admin") ||
      (user && user.includes("' OR '1'='1"))) {
    return res.json({ ok: true, user: "admin", token: "lab-token-admin" });
  }
  res.json({ ok: false });
});

// path traversal
app.get("/file", (req, res) => {
  const name = req.query.name || "";
  // NOTE: no sanitization — deliberate
  const full = path.join(__dirname, name);
  try {
    const data = fs.readFileSync(full);
    res.type("text/plain").send(data);
  } catch (e) {
    res.status(404).send("not found");
  }
});

// debug leak
app.get("/debug", (req, res) => {
  res.json({
    env: process.env,
    cwd: process.cwd(),
    node: process.version,
    argv: process.argv,
  });
});

app.listen(3000, "0.0.0.0", () => {
  console.log("vuln-node listening on 0.0.0.0:3000");
});
