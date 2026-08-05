const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'data', 'zeadx_ping.db');
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');

// Bảng lưu trữ key kích hoạt
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

module.exports = db;
