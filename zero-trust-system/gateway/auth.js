'use strict';
/**
 * Endpoint /auth/* yang ditangani langsung oleh gateway.
 * Ini adalah bagian Policy Administrator (PA): menerbitkan, memperbarui, dan mencabut kredensial sesi.
 *
 *   POST /auth/login    kredensial valid + device terdaftar  -> access token + refresh token
 *   POST /auth/refresh  refresh token valid dan belum dicabut -> access token baru
 *   POST /auth/logout   refresh token valid dan belum dicabut -> refresh token dicabut
 *   POST /auth/service  client_id + client_secret valid       -> token service (5 menit)
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const { db } = require('../shared/database');
const { TOKEN } = require('../shared/config');
const { signAccessToken, signServiceToken, sha256Hex, newRefreshToken } = require('../shared/security');
const { logDecision } = require('./auditLogger');

const router = express.Router();
router.use(express.json({ limit: '10kb' }));

const stmts = {
  userByName: db.prepare('SELECT id, username, password_hash, role FROM users WHERE username = ?'),
  userById: db.prepare('SELECT id, username, role FROM users WHERE id = ?'),
  deviceOk: db.prepare('SELECT 1 AS ok FROM devices WHERE user_id = ? AND device_id = ?'),
  insertSession: db.prepare(
    'INSERT INTO refresh_tokens (token_hash, user_id, device_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'
  ),
  sessionByHash: db.prepare('SELECT id, user_id, device_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?'),
  revokeSession: db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE id = ?'),
  clientById: db.prepare('SELECT client_id, secret_hash FROM service_clients WHERE client_id = ?'),
};

// Hash palsu agar waktu respons sama baik user ada maupun tidak (mencegah user enumeration lewat timing).
const DUMMY_HASH = bcrypt.hashSync('hash-palsu-untuk-menyamakan-waktu', 10);

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const nowSec = () => Math.floor(Date.now() / 1000);
const isNonEmptyString = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max;

function meta(req) {
  return {
    method: req.method,
    endpoint: req.originalUrl.split('?')[0],
    device: req.get('X-Device-ID') || '-',
    ip: req.socket.remoteAddress,
  };
}

/** Mencatat audit lalu membalas klien. Semua keputusan /auth/* lewat sini agar tidak ada yang lolos dari log. */
function respond(req, res, { status, subject, subjectType, allow, reason, body }) {
  logDecision({ ...meta(req), subject, subjectType, decision: allow ? 'ALLOW' : 'DENY', reason });
  return res.status(status).json(body ?? { error: status === 401 ? 'Tidak terautentikasi' : 'Akses ditolak', reason });
}

// ------------------------------------------------------------------ POST /auth/login
router.post(
  '/login',
  wrap(async (req, res) => {
    const { username, password } = req.body || {};
    if (!isNonEmptyString(username, 64) || !isNonEmptyString(password, 128)) {
      return respond(req, res, {
        status: 400, subject: 'anonymous', subjectType: 'unknown', allow: false,
        reason: 'format username atau password tidak valid',
      });
    }

    const user = stmts.userByName.get(username);
    const passwordOk = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !passwordOk) {
      // Pesan ke klien sama untuk "user tidak ada" dan "password salah".
      return respond(req, res, {
        status: 401, subject: `${username.slice(0, 40)} (belum terverifikasi)`, subjectType: 'user', allow: false,
        reason: 'kredensial tidak valid',
      });
    }

    // VERIFIKASI KONTEKS: kredensial benar saja tidak cukup, device juga harus terdaftar.
    const deviceId = req.get('X-Device-ID');
    if (!deviceId || !stmts.deviceOk.get(user.id, deviceId)) {
      return respond(req, res, {
        status: 403, subject: `${user.username} (${user.role})`, subjectType: 'user', allow: false,
        reason: 'device tidak terdaftar untuk user ini',
      });
    }

    // Satu login = satu sesi. Refresh token disimpan sebagai hash sehingga bisa dicabut dan tidak
    // bisa dibaca dari database.
    const refreshToken = newRefreshToken();
    const created = nowSec();
    const info = stmts.insertSession.run(sha256Hex(refreshToken), user.id, deviceId, created, created + TOKEN.refreshTtlSeconds);
    const accessToken = signAccessToken({ userId: user.id, role: user.role, sid: Number(info.lastInsertRowid), deviceId });

    return respond(req, res, {
      status: 200, subject: `${user.username} (${user.role})`, subjectType: 'user', allow: true, reason: 'login berhasil',
      body: {
        token_type: 'Bearer',
        access_token: accessToken,
        expires_in: 600,
        refresh_token: refreshToken,
        refresh_expires_in: TOKEN.refreshTtlSeconds,
        role: user.role,
      },
    });
  })
);

/** Mengambil sesi dari refresh token dan memastikan masih valid. Mengembalikan {session} atau {fail}. */
function loadActiveSession(refreshToken) {
  if (!isNonEmptyString(refreshToken, 200)) return { fail: 'refresh_token tidak ada atau formatnya salah' };
  const session = stmts.sessionByHash.get(sha256Hex(refreshToken));
  if (!session) return { fail: 'refresh token tidak dikenal' };
  if (session.revoked) return { fail: 'refresh token sudah dicabut' };
  if (session.expires_at <= nowSec()) return { fail: 'refresh token kedaluwarsa' };
  return { session };
}

// ------------------------------------------------------------------ POST /auth/refresh
router.post(
  '/refresh',
  wrap(async (req, res) => {
    const { session, fail } = loadActiveSession((req.body || {}).refresh_token);
    if (fail) {
      return respond(req, res, { status: 401, subject: 'anonymous', subjectType: 'unknown', allow: false, reason: fail });
    }
    const user = stmts.userById.get(session.user_id);
    const who = user ? `${user.username} (${user.role})` : `user#${session.user_id}`;
    if (!user) {
      return respond(req, res, { status: 401, subject: who, subjectType: 'user', allow: false, reason: 'user tidak ditemukan' });
    }

    // Penguatan di atas syarat soal: refresh token terikat ke device saat login.
    // Token yang dicuri dan dipakai dari perangkat lain tidak bisa menghasilkan access token baru.
    const deviceId = req.get('X-Device-ID');
    if (!deviceId || deviceId !== session.device_id || !stmts.deviceOk.get(user.id, deviceId)) {
      return respond(req, res, {
        status: 403, subject: who, subjectType: 'user', allow: false,
        reason: 'device tidak cocok dengan device saat login',
      });
    }

    const accessToken = signAccessToken({ userId: user.id, role: user.role, sid: session.id, deviceId });
    return respond(req, res, {
      status: 200, subject: who, subjectType: 'user', allow: true, reason: 'access token diperbarui',
      body: { token_type: 'Bearer', access_token: accessToken, expires_in: 600 },
    });
  })
);

// ------------------------------------------------------------------ POST /auth/logout
router.post(
  '/logout',
  wrap(async (req, res) => {
    const { session, fail } = loadActiveSession((req.body || {}).refresh_token);
    if (fail) {
      return respond(req, res, { status: 401, subject: 'anonymous', subjectType: 'unknown', allow: false, reason: fail });
    }
    stmts.revokeSession.run(session.id);
    const user = stmts.userById.get(session.user_id);
    return respond(req, res, {
      status: 200, subject: user ? `${user.username} (${user.role})` : `user#${session.user_id}`, subjectType: 'user',
      allow: true, reason: 'refresh token dicabut (logout)',
      body: { message: 'Logout berhasil, refresh token dan sesi dicabut' },
    });
  })
);

// ------------------------------------------------------------------ POST /auth/service
router.post(
  '/service',
  wrap(async (req, res) => {
    const { client_id: clientId, client_secret: clientSecret } = req.body || {};
    if (!isNonEmptyString(clientId, 64) || !isNonEmptyString(clientSecret, 256)) {
      return respond(req, res, {
        status: 400, subject: 'anonymous', subjectType: 'service', allow: false,
        reason: 'format client_id atau client_secret tidak valid',
      });
    }
    const client = stmts.clientById.get(clientId);
    const ok = await bcrypt.compare(clientSecret, client ? client.secret_hash : DUMMY_HASH);
    if (!client || !ok) {
      return respond(req, res, {
        status: 401, subject: `service:${clientId.slice(0, 40)} (belum terverifikasi)`, subjectType: 'service', allow: false,
        reason: 'client_id atau client_secret tidak valid',
      });
    }
    return respond(req, res, {
      status: 200, subject: `service:${client.client_id}`, subjectType: 'service', allow: true, reason: 'token service diterbitkan',
      body: { token_type: 'Bearer', access_token: signServiceToken(client.client_id), expires_in: 300, role: 'service' },
    });
  })
);

// Path /auth/* lain yang tidak dikenal.
router.use((req, res) =>
  respond(req, res, { status: 404, subject: 'anonymous', subjectType: 'unknown', allow: false, reason: 'endpoint auth tidak dikenal' })
);

module.exports = router;
