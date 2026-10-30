'use strict';
/**
 * Audit log (NIST SP 800-207: data source untuk analisis dan pemantauan).
 * Setiap keputusan akses dicatat: waktu, subjek, endpoint, device, hasil (ALLOW/DENY), dan alasan.
 * Hanya gateway yang menulis ke tabel ini.
 */
const { db } = require('../shared/database');

const insert = db.prepare(`
  INSERT INTO audit_logs (ts, subject, subject_type, method, endpoint, device, ip, decision, reason)
  VALUES (@ts, @subject, @subjectType, @method, @endpoint, @device, @ip, @decision, @reason)
`);

// Header dan path dikontrol penyerang. Karakter kontrol dibuang agar tidak bisa memalsukan
// baris log (log injection), dan panjangnya dibatasi agar log tidak bisa dibengkakkan.
const clean = (value, max) => String(value ?? '-').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max);

/**
 * Mencatat satu keputusan. Melempar error jika gagal menulis, dan pemanggil (gateway)
 * memperlakukannya sebagai fail closed: tanpa jejak audit, request tidak diteruskan.
 */
function logDecision({ subject, subjectType, method, endpoint, device, ip, decision, reason }) {
  const row = {
    ts: new Date().toISOString(),
    subject: clean(subject, 100),
    subjectType: clean(subjectType, 20),
    method: clean(method, 10),
    endpoint: clean(endpoint, 200),
    device: clean(device, 100),
    ip: clean(ip, 64),
    decision,
    reason: clean(reason, 300),
  };
  insert.run(row);
  console.log(
    `[AUDIT] ${row.ts} ${row.decision.padEnd(5)} subjek=${row.subject} ${row.method} ${row.endpoint} device=${row.device} alasan="${row.reason}"`
  );
  return row;
}

module.exports = { logDecision };
