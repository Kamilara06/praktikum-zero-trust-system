'use strict';
/**
 * Koneksi SQLite bersama (better-sqlite3) dan definisi skema.
 * Satu file database dipakai oleh gateway, Service Nilai, dan Service Transkrip,
 * termasuk tabel audit_logs yang hanya ditulis oleh gateway.
 */
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const { DB_PATH } = require('./config');

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma('busy_timeout = 5000'); // tiga proses berbagi satu file, tunggu dulu jika terkunci
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Urutan drop: tabel anak dulu agar tidak melanggar foreign key.
const TABLES = ['audit_logs', 'refresh_tokens', 'transkrip', 'nilai', 'kelas', 'devices', 'service_clients', 'users'];

function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      nama          TEXT NOT NULL,
      role          TEXT NOT NULL CHECK (role IN ('mahasiswa','dosen','admin')),
      nim           TEXT UNIQUE            -- hanya terisi untuk mahasiswa
    );

    -- Device terdaftar per user (dipakai untuk verifikasi konteks X-Device-ID)
    CREATE TABLE IF NOT EXISTS devices (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_id TEXT NOT NULL,
      UNIQUE (user_id, device_id)
    );

    -- Kredensial machine-to-machine (Service Nilai). Secret disimpan sebagai hash bcrypt.
    CREATE TABLE IF NOT EXISTS service_clients (
      client_id   TEXT PRIMARY KEY,
      secret_hash TEXT NOT NULL,
      nama        TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS kelas (
      id       TEXT PRIMARY KEY,
      nama_mk  TEXT NOT NULL,
      dosen_id INTEGER NOT NULL REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS nilai (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      kelas_id     TEXT NOT NULL REFERENCES kelas(id),
      mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
      nilai_angka  REAL NOT NULL CHECK (nilai_angka BETWEEN 0 AND 100),
      nilai_huruf  TEXT NOT NULL,
      is_final     INTEGER NOT NULL DEFAULT 0 CHECK (is_final IN (0,1)),
      updated_at   TEXT NOT NULL,
      UNIQUE (kelas_id, mahasiswa_id)
    );

    CREATE TABLE IF NOT EXISTS transkrip (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      nim         TEXT NOT NULL,
      kelas_id    TEXT NOT NULL,
      nama_mk     TEXT NOT NULL,
      nilai_angka REAL NOT NULL,
      nilai_huruf TEXT NOT NULL,
      synced_at   TEXT NOT NULL,
      UNIQUE (nim, kelas_id)
    );

    -- Satu baris = satu sesi login. Hanya hash refresh token yang disimpan, bukan token aslinya.
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT NOT NULL UNIQUE,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_id  TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked    INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0,1))
    );

    -- Jejak audit keputusan akses. Ditulis oleh gateway saja.
    CREATE TABLE IF NOT EXISTS audit_logs (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      ts           TEXT NOT NULL,
      subject      TEXT NOT NULL,
      subject_type TEXT NOT NULL,
      method       TEXT NOT NULL,
      endpoint     TEXT NOT NULL,
      device       TEXT NOT NULL,
      ip           TEXT,
      decision     TEXT NOT NULL CHECK (decision IN ('ALLOW','DENY')),
      reason       TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);
  `);
}

function dropSchema() {
  for (const table of TABLES) db.exec(`DROP TABLE IF EXISTS ${table}`);
}

initSchema();

module.exports = { db, initSchema, dropSchema };
