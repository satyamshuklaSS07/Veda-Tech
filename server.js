const express = require("express"), helmet = require("helmet"), rateLimit = require("express-rate-limit");
const fs = require("fs"), path = require("path");
const app = express();
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'none'"], scriptSrc: ["'unsafe-inline'"], styleSrc: ["'unsafe-inline'", "https://fonts.googleapis.com"],
  fontSrc: ["https://fonts.gstatic.com"], imgSrc: ["data:"], connectSrc: ["'self'"], baseUri: ["'none'"],
  formAction: ["'self'"], frameAncestors: ["'none'"] } } }));
app.use(express.json({ limit: "10kb" }));
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });
const DATA = path.join(__dirname, "data");
fs.mkdirSync(DATA, { recursive: true });
const clean = (v, n) => String(v ?? "").replace(/[\u0000-\u001f<>]/g, " ").trim().slice(0, n);
const okEmail = e => /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(e);
const save = (file, rec) => fs.appendFileSync(path.join(DATA, file), JSON.stringify(rec) + "\n");

app.post("/api/apply", limiter, (req, res) => {
  const b = req.body || {};
  if (b.website) return res.json({ ok: true }); // honeypot: bots fill this
  const r = { name: clean(b.name, 60), email: clean(b.email, 100), phone: clean(b.phone, 16),
    track: clean(b.track, 60), message: clean(b.message, 400), at: new Date().toISOString() };
  if (r.name.length < 2 || !okEmail(r.email) || !/^[+\d][\d\s-]{8,14}$/.test(r.phone)) return res.status(400).json({ ok: false });
  save("applications.jsonl", r);
  res.json({ ok: true });
});

app.post("/api/contact", limiter, (req, res) => {
  const b = req.body || {};
  if (b.website) return res.json({ ok: true });
  const r = { name: clean(b.name, 60), email: clean(b.email, 100), message: clean(b.message, 600), at: new Date().toISOString() };
  if (r.name.length < 2 || !okEmail(r.email) || r.message.length < 10) return res.status(400).json({ ok: false });
  save("messages.jsonl", r);
  res.json({ ok: true });
});

// Only index.html is served, so server.js and data/ can never be downloaded.
app.get("/", (q, s) => s.sendFile(path.join(__dirname, "index.html")));
app.use((e, q, s, n) => s.status(400).json({ ok: false }));
app.listen(process.env.PORT || 3000, () => console.log("Veda Tech running"));
