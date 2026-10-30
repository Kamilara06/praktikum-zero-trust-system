'use strict';
/**
 * Fungsi keamanan bersama: penerbitan dan verifikasi JWT, hash, dan pembanding rahasia.
 * Dipakai oleh gateway (menerbitkan dan memverifikasi) dan oleh kedua service (memverifikasi ulang).
 */
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { JWT_SECRET, TOKEN } = require('./config');

const USER_ROLES = ['mahasiswa', 'dosen', 'admin'];

/**
 * Access token user (10 menit). Klaim minimal sub dan role.
 * Klaim tambahan: sid (id sesi, agar logout langsung mematikan token) dan dev (device saat login).
 * Atribut kepemilikan data (NIM, kelas yang diampu) sengaja TIDAK ditaruh di token,
 * karena keputusan itu dibaca ulang dari database oleh Policy Engine.
 */
function signAccessToken({ userId, role, sid, deviceId }) {
  return jwt.sign({ role, token_use: 'access', sid, dev: deviceId }, JWT_SECRET, {
    algorithm: 'HS256',
    subject: String(userId),
    issuer: TOKEN.issuer,
    audience: TOKEN.audience,
    expiresIn: TOKEN.accessTtl,
  });
}

/** Token service (5 menit) dengan role "service" untuk panggilan antar-service. */
function signServiceToken(clientId) {
  return jwt.sign({ role: 'service', token_use: 'service' }, JWT_SECRET, {
    algorithm: 'HS256',
    subject: clientId,
    issuer: TOKEN.issuer,
    audience: TOKEN.audience,
    expiresIn: TOKEN.serviceTtl,
  });
}

/**
 * Verifikasi tanda tangan, masa berlaku, issuer, audience, dan bentuk klaim.
 * Algoritma dikunci ke HS256 sehingga token "alg: none" atau algoritma lain ditolak.
 * Melempar error jika tidak valid.
 */
function verifyToken(token) {
  const payload = jwt.verify(token, JWT_SECRET, {
    algorithms: ['HS256'],
    issuer: TOKEN.issuer,
    audience: TOKEN.audience,
  });

  const isUserToken =
    payload.token_use === 'access' && USER_ROLES.includes(payload.role) && Number.isInteger(payload.sid) && payload.sub;
  const isServiceToken = payload.token_use === 'service' && payload.role === 'service' && payload.sub;

  if (!isUserToken && !isServiceToken) throw new Error('klaim token tidak lengkap atau tidak konsisten');
  return payload;
}

const sha256Hex = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

/** Perbandingan rahasia dengan waktu konstan agar tidak bocor lewat timing attack. */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/** Refresh token buram (opaque), 256 bit acak. Yang disimpan di DB hanya hash-nya. */
const newRefreshToken = () => crypto.randomBytes(32).toString('base64url');

module.exports = { signAccessToken, signServiceToken, verifyToken, sha256Hex, safeEqual, newRefreshToken, USER_ROLES };
