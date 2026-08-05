const express = require('express');
const router = express.Router();
const db = require('../db');
const generateKey = require('../utils/generateKey');
const adminAuth = require('../utils/adminAuth');

/**
 * POST /api/keys/generate
 * Tạo key mới (chỉ admin). Body: { label?: string, expiresInDays?: number }
 */
router.post('/generate', adminAuth, (req, res) => {
  const { label, expiresInDays } = req.body || {};

  let keyValue;
  let attempts = 0;
  const insert = db.prepare(
    `INSERT INTO keys (key_value, label, expires_at) VALUES (?, ?, ?)`
  );

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
      if (attempts >= 5) {
        return res.status(500).json({ error: 'Không thể sinh key duy nhất, thử lại sau.' });
      }
    }
  }

  return res.status(201).json({
    key: keyValue,
    label: label || null,
    expires_at: expiresAt,
  });
});

/**
 * POST /api/keys/verify
 * Kiểm tra key có hợp lệ không. Body: { key: string }
 */
router.post('/verify', (req, res) => {
  const { key } = req.body || {};

  if (!key) {
    return res.status(400).json({ valid: false, reason: 'Thiếu key.' });
  }

  const row = db.prepare(`SELECT * FROM keys WHERE key_value = ?`).get(key);

  if (!row) {
    return res.status(404).json({ valid: false, reason: 'Key không tồn tại.' });
  }

  if (row.revoked) {
    return res.status(403).json({ valid: false, reason: 'Key đã bị thu hồi.' });
  }

  if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) {
    return res.status(403).json({ valid: false, reason: 'Key đã hết hạn.' });
  }

  db.prepare(
    `UPDATE keys SET last_used_at = datetime('now'), used_count = used_count + 1 WHERE id = ?`
  ).run(row.id);

  return res.json({
    valid: true,
    label: row.label,
    expires_at: row.expires_at,
  });
});

/**
 * POST /api/keys/revoke
 * Thu hồi key (chỉ admin). Body: { key: string }
 */
router.post('/revoke', adminAuth, (req, res) => {
  const { key } = req.body || {};
  if (!key) {
    return res.status(400).json({ error: 'Thiếu key.' });
  }

  const result = db.prepare(`UPDATE keys SET revoked = 1 WHERE key_value = ?`).run(key);

  if (result.changes === 0) {
    return res.status(404).json({ error: 'Không tìm thấy key.' });
  }

  return res.json({ success: true, message: `Key ${key} đã bị thu hồi.` });
});

/**
 * GET /api/keys
 * Liệt kê toàn bộ key (chỉ admin).
 */
router.get('/', adminAuth, (req, res) => {
  const rows = db.prepare(`SELECT * FROM keys ORDER BY created_at DESC`).all();
  return res.json(rows);
});

module.exports = router;
