'use strict';
/**
 * POLICY ENGINE (PE) sesuai NIST SP 800-207.
 *
 * Menerima subjek yang SUDAH terverifikasi oleh gateway (token valid, sesi aktif, device cocok)
 * beserta request-nya, lalu mengembalikan keputusan allow/deny disertai alasan.
 *
 * Kebijakan yang bergantung pada kepemilikan data (ABAC) tidak bisa diputuskan dari isi token saja,
 * jadi atributnya dibaca dari database: NIM mahasiswa, dosen pengampu kelas, dan status final nilai.
 *
 * Prinsip yang dijalankan di sini:
 *   - Default deny: endpoint yang tidak punya aturan ditolak.
 *   - Least privilege: tiap aturan hanya membuka role dan kondisi yang dibutuhkan.
 */
const { db } = require('../shared/database');
const { ACCESS_HOURS, SERVICE_CLIENT_ID, isWithinAccessHours } = require('../shared/config');

const allow = (reason) => ({ allow: true, status: 200, reason });
const deny = (status, reason) => ({ allow: false, status, reason });

const q = {
  nilaiWithOwner: db.prepare(
    'SELECT n.id, n.is_final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?'
  ),
  kelas: db.prepare('SELECT id, dosen_id FROM kelas WHERE id = ?'),
};

const hasRole = (subject, ...roles) => subject.type === 'user' && roles.includes(subject.role);
const outsideHours = () => deny(403, `di luar jam akses perubahan nilai (${ACCESS_HOURS.label})`);

/**
 * Tabel kebijakan. Setiap aturan: method + pola path + service tujuan + fungsi keputusan.
 * Ini adalah implementasi langsung dari tabel kebijakan akses pada soal.
 */
const RULES = [
  {
    name: 'GET /nilai',
    method: 'GET',
    pattern: /^\/nilai\/?$/,
    target: 'nilai',
    // Mahasiswa dan dosen. Penyaringan "hanya milik sendiri" dan "hanya kelas yang diampu"
    // dilakukan lagi oleh Service Nilai pada query datanya.
    decide({ subject, query }) {
      if (!hasRole(subject, 'mahasiswa', 'dosen')) return deny(403, `role ${subject.role} tidak boleh membaca nilai`);
      if (query.kelas_id !== undefined && typeof query.kelas_id !== 'string') return deny(400, 'parameter kelas_id tidak valid');
      if (subject.role === 'dosen' && query.kelas_id !== undefined) {
        const kelas = q.kelas.get(query.kelas_id);
        if (!kelas || kelas.dosen_id !== subject.id) return deny(403, 'kelas bukan diampu dosen ini');
      }
      return allow(subject.role === 'mahasiswa' ? 'mahasiswa membaca nilai miliknya' : 'dosen membaca nilai kelas yang diampu');
    },
  },
  {
    name: 'PUT /nilai/:id',
    method: 'PUT',
    pattern: /^\/nilai\/(\d{1,9})\/?$/,
    target: 'nilai',
    // Dosen pengampu, nilai belum final, dan dalam jam akses.
    decide({ subject, params, now }) {
      if (!hasRole(subject, 'dosen')) return deny(403, `role ${subject.role} tidak boleh mengubah nilai`);
      const row = q.nilaiWithOwner.get(Number(params[0]));
      if (!row) return deny(404, 'data nilai tidak ditemukan');
      if (row.dosen_id !== subject.id) return deny(403, 'kelas bukan diampu dosen ini');
      if (row.is_final) return deny(403, 'nilai sudah final dan tidak boleh diubah');
      if (!isWithinAccessHours(now)) return outsideHours();
      return allow('dosen pengampu mengubah nilai yang belum final dalam jam akses');
    },
  },
  {
    name: 'POST /kelas/:id/finalisasi',
    method: 'POST',
    pattern: /^\/kelas\/([A-Za-z0-9_-]{1,20})\/finalisasi\/?$/,
    target: 'nilai',
    // Dosen pengampu dan dalam jam akses.
    decide({ subject, params, now }) {
      if (!hasRole(subject, 'dosen')) return deny(403, `role ${subject.role} tidak boleh memfinalisasi nilai`);
      const kelas = q.kelas.get(params[0]);
      if (!kelas) return deny(404, 'kelas tidak ditemukan');
      if (kelas.dosen_id !== subject.id) return deny(403, 'kelas bukan diampu dosen ini');
      if (!isWithinAccessHours(now)) return outsideHours();
      return allow('dosen pengampu memfinalisasi nilai kelas dalam jam akses');
    },
  },
  {
    name: 'GET /transkrip/:nim',
    method: 'GET',
    pattern: /^\/transkrip\/([A-Za-z0-9-]{3,20})\/?$/,
    target: 'transkrip',
    // Mahasiswa hanya NIM sendiri (NIM dibaca dari DB), admin boleh semua NIM.
    decide({ subject, params }) {
      if (hasRole(subject, 'admin')) return allow('admin membaca transkrip');
      if (hasRole(subject, 'mahasiswa')) {
        return subject.nim === params[0] ? allow('mahasiswa membaca transkrip sendiri') : deny(403, 'NIM bukan milik mahasiswa ini');
      }
      return deny(403, `role ${subject.role} tidak boleh membaca transkrip`);
    },
  },
  {
    name: 'POST /transkrip/sinkron',
    method: 'POST',
    pattern: /^\/transkrip\/sinkron\/?$/,
    target: 'transkrip',
    // Hanya token service dari Service Nilai. Token user apa pun, termasuk admin, ditolak.
    decide({ subject }) {
      if (subject.type !== 'service') return deny(403, 'endpoint sinkron hanya untuk token service, token user ditolak');
      if (subject.clientId !== SERVICE_CLIENT_ID) return deny(403, 'service ini tidak berhak memanggil sinkron');
      return allow('Service Nilai menyinkronkan transkrip');
    },
  },
];

/**
 * @param {object} input
 * @param {{type:'user'|'service', id?:number, username?:string, role:string, nim?:string|null, clientId?:string}} input.subject
 * @param {string} input.method
 * @param {string} input.path   path tanpa query string
 * @param {object} input.query
 * @param {Date}   input.now    waktu yang dipakai untuk pemeriksaan jam akses
 * @returns {{allow:boolean, status:number, reason:string, target:string|null, rule:string|null}}
 */
function evaluate({ subject, method, path, query = {}, now }) {
  for (const rule of RULES) {
    if (rule.method !== method) continue;
    const match = rule.pattern.exec(path);
    if (!match) continue;
    const decision = rule.decide({ subject, params: match.slice(1), query, now });
    return { ...decision, target: rule.target, rule: rule.name };
  }
  // Default deny: tidak ada aturan yang cocok.
  return { allow: false, status: 403, reason: 'tidak ada kebijakan untuk endpoint ini (default deny)', target: null, rule: null };
}

module.exports = { evaluate, RULES };
