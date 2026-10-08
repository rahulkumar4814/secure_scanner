// INTENTIONALLY VULNERABLE demo application - for SecureScan AI testing only. Do not deploy.
const express = require("express");
const { exec } = require("child_process");
const _ = require("lodash");
const mysql = require("mysql");

const app = express();
app.use(express.json());
const db = mysql.createConnection({ host: "localhost", user: "app", database: "shop" });

// Fake demo credential (not a real key) - should be detected by gitleaks
const secret_token = "4c7b2e9f1a8d3c6e0b5f9a2d7e1c4b8f6a3d0e9c";

app.get("/product", (req, res) => {
  // SQL injection (CWE-89)
  db.query("SELECT * FROM products WHERE id = " + req.query.id, (err, rows) => res.json(rows));
});

app.get("/lookup", (req, res) => {
  // OS command injection (CWE-78)
  exec("nslookup " + req.query.domain, (err, out) => res.send(out));
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr))); // code injection (CWE-95)
});

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + req.query.name + "</h1>"); // reflected XSS (CWE-79)
});

app.post("/merge", (req, res) => {
  res.json(_.merge({}, req.body)); // prototype pollution with vulnerable lodash (CWE-1321)
});

app.listen(3000);
