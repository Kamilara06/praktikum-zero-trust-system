'use strict';
/**
 * API GATEWAY (port 3000) = POLICY ENFORCEMENT POINT (PEP) + Policy Engine / Administrator (PE/PA).
 *
 * Satu-satunya pintu masuk. Setiap request non-auth melewati urutan ini:
 *   (a) access token valid                    (never trust, always verify)
 *   (b) device terdaftar milik user           (verifikasi konteks)
 *   (c) policy.js memutuskan allow/deny       (ABAC dengan atribut dari database)
 *   (d) jam akses untuk ubah/finalisasi nilai (bagian dari policy.js)
 *   (e) keputusan dicatat ke audit_logs       (ALLOW maupun DENY)
 *   (f) jika ALLOW, diteruskan ke service dengan X-Gateway-Secret
 */
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { db } = require('../shared/database');
const { PORTS, HOST, GATEWAY_SECRET, TARGETS, getNow, usingDefaultSecrets } = require('../shared/config');
const { verifyToken } = require('../shared/security');
const { errorHandler } = require('../shared/guard');
const { evaluate } = require('./policy');
const { logDecision } = require('./auditLogger');
const authRouter = require('./auth');

const stmts = {
  userById: db.prepare('SELECT id, username, role, nim FROM users WHERE id = ?'),
  sessionById: db.prepare('SELECT id, user_id, device_id, expires_at, revoked FROM refresh_tokens WHERE id = ?'),
  deviceOk: db.prepare('SELECT 1 AS ok FROM devices WHERE user_id = ? AND device_id = ?'),
  clientById: db.prepare('SELECT client_id FROM service_clients WHERE client_id = ?'),
};

// ---------------------------------------------------------------- proxy ke service
// (f) Gateway menyisipkan X-Gateway-Secret. Nilai dari klien selalu ditimpa.
// Body request tidak di-parse di gateway, jadi stream langsung diteruskan apa adanya.
function makeProxy(target) {
  return createProxyMiddleware({
    target,
    changeOrigin: false,
    xfwd: true,
    proxyTimeout: 10000,
    on: {
      proxyReq: (proxyReq) => {
        proxyReq.setHeader('X-Gateway-Secret', GATEWAY_SECRET);
      },
      error: (err, req, res) => {
        console.error('[PROXY]', err.code || err.message);
        if (res && typeof res.writeHead === 'function' && !res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Service tidak dapat dihubungi' }));
        }
      },
    },
  });
}
const proxies = { nilai: makeProxy(TARGETS.nilai), transkrip: makeProxy(TARGETS.transkrip) };

const STATUS_LABEL = { 400: 'Permintaan tidak valid', 401: 'Tidak terautentikasi', 404: 'Tidak ditemukan' };

// ---------------------------------------------------------------- PEP
function enforce(req, res) {
  const meta = {
    method: req.method,
    endpoint: req.path,
    device: req.get('X-Device-ID') || '-',
    ip: req.socket.remoteAddress,
  };

  // Mencatat DENY lalu membalas klien.
  const reject = (status, reason, who = { subject: 'anonymous', subjectType: 'unknown' }) => {
    logDecision({ ...meta, ...who, decision: 'DENY', reason });
    return res.status(status).json({ error: STATUS_LABEL[status] || 'Akses ditolak', reason });
  };

  try {
    // (a) Access token wajib ada dan valid (tanda tangan, masa berlaku, issuer, audience).
    const bearer = /^Bearer\s+(\S+)$/i.exec(req.get('Authorization') || '');
    if (!bearer) return reject(401, 'Authorization Bearer token tidak ada');

    let claims;
    try {
      claims = verifyToken(bearer[1]);
    } catch (err) {
      return reject(401, err.name === 'TokenExpiredError' ? 'token kedaluwarsa' : 'token tidak valid');
    }

    let subject;
    let who;

    if (claims.token_use === 'access') {
      // Role dan keberadaan user dibaca ulang dari DB, bukan dipercaya dari token.
      const user = stmts.userById.get(Number(claims.sub));
      if (!user || user.role !== claims.role) return reject(401, 'user tidak ditemukan atau role sudah berubah');
      who = { subject: `${user.username} (${user.role})`, subjectType: 'user' };

      // Sesi harus masih aktif. Logout langsung mematikan access token yang masih berlaku.
      const session = stmts.sessionById.get(claims.sid);
      const nowSec = Math.floor(Date.now() / 1000);
      if (!session || session.user_id !== user.id || session.revoked || session.expires_at <= nowSec) {
        return reject(401, 'sesi tidak aktif (sudah logout atau dicabut)', who);
      }

      // (b) Verifikasi konteks: device harus terdaftar milik user DAN sama dengan device saat login.
      const deviceId = req.get('X-Device-ID');
      if (!deviceId) return reject(403, 'header X-Device-ID tidak ada', who);
      if (!stmts.deviceOk.get(user.id, deviceId)) return reject(403, 'device tidak terdaftar untuk user ini', who);
      if (deviceId !== session.device_id) return reject(403, 'device berbeda dengan device saat login', who);

      subject = { type: 'user', id: user.id, username: user.username, role: user.role, nim: user.nim };
    } else {
      // Token service: client harus masih terdaftar. Tidak ada konteks device untuk mesin.
      const client = stmts.clientById.get(claims.sub);
      if (!client) return reject(401, 'client service tidak dikenal');
      who = { subject: `service:${client.client_id}`, subjectType: 'service' };
      subject = { type: 'service', clientId: client.client_id, role: 'service' };
    }

    // (c) + (d) Policy Engine memutuskan, termasuk kepemilikan data dan jam akses.
    const decision = evaluate({ subject, method: req.method, path: req.path, query: req.query, now: getNow() });

    // (e) Setiap keputusan dicatat. Jika pencatatan gagal, lompat ke catch (fail closed).
    logDecision({ ...meta, ...who, decision: decision.allow ? 'ALLOW' : 'DENY', reason: decision.reason });

    if (!decision.allow) {
      return res.status(decision.status).json({ error: STATUS_LABEL[decision.status] || 'Akses ditolak', reason: decision.reason });
    }

    // (f) Diteruskan hanya ke service yang ditentukan aturan yang cocok.
    return proxies[decision.target](req, res, (err) => {
      if (err && !res.headersSent) res.status(502).json({ error: 'Gagal meneruskan request' });
    });
  } catch (err) {
    // FAIL CLOSED: kegagalan internal berarti request tidak diteruskan.
    console.error('[GATEWAY ERROR]', err);
    if (!res.headersSent) res.status(500).json({ error: 'Kesalahan internal, request ditolak' });
    return undefined;
  }
}

// ---------------------------------------------------------------- aplikasi
const app = express();
app.disable('x-powered-by');

app.use('/auth', authRouter); // /auth/* ditangani gateway sendiri (PE/PA)
app.use(enforce); // semua path lain wajib lewat PEP
app.use(errorHandler);

app.listen(PORTS.gateway, HOST, () => {
  console.log(`[GATEWAY] PEP + PE/PA aktif di http://${HOST}:${PORTS.gateway}`);
  console.log(`[GATEWAY] Service nilai -> ${TARGETS.nilai} | transkrip -> ${TARGETS.transkrip}`);
  if (usingDefaultSecrets) console.warn('[GATEWAY] PERINGATAN: memakai rahasia default. Cukup untuk demo, ganti lewat env di luar demo.');
});
