'use strict';
/**
 * Middleware pertahanan berlapis untuk setiap Resource Service (prinsip "assume breach").
 * Gateway sudah memeriksa semuanya, tetapi service tidak mempercayai gateway begitu saja.
 */
const { GATEWAY_SECRET } = require('./config');
const { verifyToken, safeEqual } = require('./security');

function zeroTrustGuard(req, res, next) {
  // LAPIS 1: hanya gateway yang tahu X-Gateway-Secret.
  // Request langsung ke port service tanpa header ini ditolak, jadi service tidak bisa di-bypass.
  const secret = req.get('X-Gateway-Secret');
  if (!secret || !safeEqual(secret, GATEWAY_SECRET)) {
    return res.status(403).json({ error: 'Ditolak', reason: 'X-Gateway-Secret tidak ada atau salah, akses harus lewat gateway' });
  }

  // LAPIS 2: gateway secret yang cocok BELUM cukup.
  // Tanda tangan dan masa berlaku token diverifikasi ulang di sini. Kalau gateway
  // atau secret-nya bocor, request tanpa token valid tetap mentok.
  const match = /^Bearer\s+(\S+)$/i.exec(req.get('Authorization') || '');
  if (!match) {
    return res.status(401).json({ error: 'Tidak terautentikasi', reason: 'Authorization Bearer token tidak ada' });
  }

  let claims;
  try {
    claims = verifyToken(match[1]);
  } catch (err) {
    const reason = err.name === 'TokenExpiredError' ? 'token kedaluwarsa' : 'token tidak valid';
    return res.status(401).json({ error: 'Tidak terautentikasi', reason });
  }

  // Identitas HANYA diambil dari token yang sudah diverifikasi, tidak pernah dari header lain.
  req.auth = { sub: claims.sub, role: claims.role, tokenUse: claims.token_use, sid: claims.sid };
  return next();
}

/** Penanganan error seragam agar stack trace tidak bocor ke klien. */
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Body bukan JSON yang valid' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Body terlalu besar' });
  console.error('[ERROR]', err);
  return res.status(500).json({ error: 'Kesalahan internal' });
}

const notFound = (req, res) => res.status(404).json({ error: 'Endpoint tidak ditemukan' });

module.exports = { zeroTrustGuard, errorHandler, notFound };
