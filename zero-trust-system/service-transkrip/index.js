'use strict';
/**
 * SERVICE TRANSKRIP (port 3002) = Resource.
 *
 * Sama seperti Service Nilai, service ini tidak mempercayai gateway begitu saja:
 * X-Gateway-Secret dan JWT diperiksa ulang, lalu role dan kepemilikan data dicek lagi.
 */
const express = require('express');
const { db } = require('../shared/database');
const { PORTS, HOST, SERVICE_CLIENT_ID } = require('../shared/config');
const { zeroTrustGuard, errorHandler, notFound } = require('../shared/guard');

const app = express();
app.disable('x-powered-by');
app.use(zeroTrustGuard);
app.use(express.json({ limit: '200kb' }));

const forbid = (res, reason, status = 403) => res.status(status).json({ error: status === 404 ? 'Tidak ditemukan' : 'Ditolak', reason });

const q = {
  userById: db.prepare('SELECT nim FROM users WHERE id = ?'),
  student: db.prepare("SELECT nim, nama FROM users WHERE nim = ? AND role = 'mahasiswa'"),
  transkrip: db.prepare(
    'SELECT kelas_id, nama_mk, nilai_angka, nilai_huruf, synced_at FROM transkrip WHERE nim = ? ORDER BY kelas_id'
  ),
  kelas: db.prepare('SELECT id, nama_mk FROM kelas WHERE id = ?'),
  finalNilai: db.prepare(
    `SELECT n.nilai_angka, n.is_final
     FROM nilai n JOIN users u ON u.id = n.mahasiswa_id
     WHERE u.nim = ? AND n.kelas_id = ?`
  ),
  upsert: db.prepare(
    `INSERT INTO transkrip (nim, kelas_id, nama_mk, nilai_angka, nilai_huruf, synced_at)
     VALUES (@nim, @kelas_id, @nama_mk, @nilai_angka, @nilai_huruf, @synced_at)
     ON CONFLICT (nim, kelas_id) DO UPDATE SET
       nama_mk = excluded.nama_mk, nilai_angka = excluded.nilai_angka,
       nilai_huruf = excluded.nilai_huruf, synced_at = excluded.synced_at`
  ),
};

// ------------------------------------------------------------------ GET /transkrip/:nim
// Mahasiswa: hanya NIM sendiri. Admin: semua NIM.
app.get('/transkrip/:nim', (req, res) => {
  if (req.auth.tokenUse !== 'access') return forbid(res, 'token service tidak boleh membaca transkrip');
  const { nim } = req.params;
  if (!/^[A-Za-z0-9-]{3,20}$/.test(nim)) return forbid(res, 'format NIM tidak valid', 400);

  if (req.auth.role === 'mahasiswa') {
    const me = q.userById.get(Number(req.auth.sub)); // NIM dari DB berdasarkan identitas di token
    if (!me || me.nim !== nim) return forbid(res, 'NIM bukan milik mahasiswa ini');
  } else if (req.auth.role !== 'admin') {
    return forbid(res, `role ${req.auth.role} tidak boleh membaca transkrip`);
  }

  const student = q.student.get(nim);
  if (!student) return forbid(res, 'NIM tidak ditemukan', 404);
  const rows = q.transkrip.all(nim);
  return res.json({ nim: student.nim, nama: student.nama, count: rows.length, transkrip: rows });
});

// ------------------------------------------------------------------ POST /transkrip/sinkron
// Hanya token service dari Service Nilai. Token user mana pun ditolak dengan 403.
app.post('/transkrip/sinkron', (req, res) => {
  if (req.auth.tokenUse !== 'service' || req.auth.role !== 'service' || req.auth.sub !== SERVICE_CLIENT_ID) {
    return forbid(res, 'endpoint sinkron hanya untuk token service dari Service Nilai');
  }

  const { kelas_id: kelasId, items } = req.body || {};
  if (typeof kelasId !== 'string' || !Array.isArray(items) || items.length === 0 || items.length > 500) {
    return forbid(res, 'body harus berisi kelas_id (string) dan items (array 1 sampai 500 elemen)', 400);
  }
  const kelas = q.kelas.get(kelasId);
  if (!kelas) return forbid(res, 'kelas tidak ditemukan', 404);

  // Walaupun pengirimnya service tepercaya, isi kirimannya tetap divalidasi terhadap database.
  // Hanya nilai yang benar-benar sudah final dan cocok yang boleh masuk transkrip.
  const rows = [];
  for (const item of items) {
    const valid =
      item && typeof item.nim === 'string' && typeof item.nilai_angka === 'number' &&
      Number.isFinite(item.nilai_angka) && item.nilai_angka >= 0 && item.nilai_angka <= 100 &&
      typeof item.nilai_huruf === 'string' && item.nilai_huruf.length > 0 && item.nilai_huruf.length <= 3;
    if (!valid) return forbid(res, 'format item tidak valid', 400);

    const stored = q.finalNilai.get(item.nim, kelasId);
    if (!stored) return forbid(res, `nilai ${item.nim} di kelas ${kelasId} tidak ditemukan`, 422);
    if (!stored.is_final) return forbid(res, `nilai ${item.nim} di kelas ${kelasId} belum final`, 409);
    if (stored.nilai_angka !== item.nilai_angka) return forbid(res, `nilai ${item.nim} tidak sama dengan data final di database`, 409);

    rows.push({
      nim: item.nim, kelas_id: kelasId, nama_mk: kelas.nama_mk,
      nilai_angka: item.nilai_angka, nilai_huruf: item.nilai_huruf, synced_at: new Date().toISOString(),
    });
  }

  db.transaction(() => rows.forEach((row) => q.upsert.run(row)))();
  return res.json({ message: 'Transkrip disinkronkan', kelas_id: kelasId, jumlah: rows.length });
});

app.use(notFound);
app.use(errorHandler);

app.listen(PORTS.transkrip, HOST, () => {
  console.log(`[TRANSKRIP] Service Transkrip aktif di http://${HOST}:${PORTS.transkrip} (hanya menerima request dari gateway)`);
});
