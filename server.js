require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ===== DATABASE =====
const db = new Database(path.join(__dirname, 'zeadx_ping.db'));
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_value TEXT UNIQUE NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    last_used_at TEXT,
    used_count INTEGER NOT NULL DEFAULT 0
  )
`);

// ===== SINH KEY =====
function generateKey(prefix = 'ZEADX') {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segment = () => {
    let s = '';
    const bytes = crypto.randomBytes(4);
    for (let i = 0; i < 4; i++) s += chars[bytes[i] % chars.length];
    return s;
  };
  return `${prefix}-${segment()}-${segment()}-${segment()}`;
}

// ===== ADMIN AUTH =====
function adminAuth(req, res, next) {
  const provided = req.headers['x-admin-secret'];
  const expected = process.env.ADMIN_SECRET;
  if (!expected) return res.status(500).json({ error: 'ADMIN_SECRET chưa cấu hình.' });
  if (!provided || provided !== expected) return res.status(401).json({ error: 'Không có quyền truy cập.' });
  next();
}

// ===== ROUTES =====
app.get('/', (req, res) => {
  res.json({ service: 'Zeadx Ping Key System', status: 'online' });
});

app.post('/api/keys/generate', adminAuth, (req, res) => {
  const { label, expiresInDays } = req.body || {};
  let keyValue;
  let attempts = 0;
  const insert = db.prepare(`INSERT INTO keys (key_value, label, expires_at) VALUES (?, ?, ?)`);
  const expiresAt = expiresInDays
    ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString()
    : null;

  while (attempts < 5) {
    keyValue = generateKey();
    try {
      insert.run(keyValue, label || null, expiresAt);
      break;
    } catch (err) {
      attempts++;
      if (attempts >= 5) return res.status(500).json({ error: 'Không thể sinh key duy nhất.' });
    }
  }
  res.status(201).json({ key: keyValue, label: label || null, expires_at: expiresAt });
});

app.post('/api/keys/verify', (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ valid: false, reason: 'Thiếu key.' });

  const row = db.prepare(`SELECT * FROM keys WHERE key_value = ?`).get(key);
  if (!row) return res.status(404).json({ valid: false, reason: 'Key không tồn tại.' });
  if (row.revoked) return res.status(403).json({ valid: false, reason: 'Key đã bị thu hồi.' });
  if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) {
    return res.status(403).json({ valid: false, reason: 'Key đã hết hạn.' });
  }

  db.prepare(`UPDATE keys SET last_used_at = datetime('now'), used_count = used_count + 1 WHERE id = ?`).run(row.id);
  res.json({ valid: true, label: row.label, expires_at: row.expires_at });
});

app.post('/api/keys/revoke', adminAuth, (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ error: 'Thiếu key.' });
  const result = db.prepare(`UPDATE keys SET revoked = 1 WHERE key_value = ?`).run(key);
  if (result.changes === 0) return res.status(404).json({ error: 'Không tìm thấy key.' });
  res.json({ success: true, message: `Key ${key} đã bị thu hồi.` });
});

app.get('/api/keys', adminAuth, (req, res) => {
  const rows = db.prepare(`SELECT * FROM keys ORDER BY created_at DESC`).all();
  res.json(rows);
});

// ===== START =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Zeadx Ping Key System đang chạy tại http://localhost:${PORT}`);
});
