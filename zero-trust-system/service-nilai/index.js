'use strict';
/**
 * SERVICE NILAI (port 3001) = Resource.
 *
 * Tidak mempercayai gateway begitu saja (assume breach):
 *   - zeroTrustGuard: menolak request tanpa X-Gateway-Secret, lalu memverifikasi ulang JWT.
 *   - Setiap endpoint mengecek ulang role, kepemilikan data, status final, dan jam akses.
 *     Data selalu disaring memakai identitas dari TOKEN, bukan dari parameter klien.
 */
const express = require('express');
const { db } = require('../shared/database');
const {
  PORTS, HOST, GATEWAY_URL, SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET, ACCESS_HOURS, isWithinAccessHours,
} = require('../shared/config');
const { zeroTrustGuard, errorHandler, notFound } = require('../shared/guard');
const { toLetter } = require('../shared/grade');

const app = express();
app.disable('x-powered-by');

// Guard dipasang SEBELUM parser body, jadi request yang tidak sah tidak sempat diproses.
app.use(zeroTrustGuard);
app.use(express.json({ limit: '10kb' }));

const forbid = (res, reason, status = 403) => res.status(status).json({ error: status === 404 ? 'Tidak ditemukan' : 'Ditolak', reason });

/** Hanya token user (bukan token service) dengan salah satu role yang disebut. */
const requireUserRole = (...roles) => (req, res, next) => {
  if (req.auth.tokenUse !== 'access' || !roles.includes(req.auth.role)) {
    return forbid(res, `role ${req.auth.role} tidak diizinkan untuk endpoint ini`);
  }
  return next();
};

const SELECT_NILAI = `
  SELECT n.id, n.kelas_id, k.nama_mk, u.nim, u.nama AS mahasiswa,
         n.nilai_angka, n.nilai_huruf, n.is_final, n.updated_at
  FROM nilai n
  JOIN kelas k ON k.id = n.kelas_id
  JOIN users u ON u.id = n.mahasiswa_id`;

const q = {
  nilaiMahasiswa: db.prepare(`${SELECT_NILAI} WHERE n.mahasiswa_id = @uid AND (@kelas IS NULL OR n.kelas_id = @kelas) ORDER BY n.kelas_id, u.nim`),
  nilaiDosen: db.prepare(`${SELECT_NILAI} WHERE k.dosen_id = @uid AND (@kelas IS NULL OR n.kelas_id = @kelas) ORDER BY n.kelas_id, u.nim`),
  kelas: db.prepare('SELECT id, nama_mk, dosen_id FROM kelas WHERE id = ?'),
  nilaiWithOwner: db.prepare('SELECT n.id, n.is_final, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?'),
  updateNilai: db.prepare('UPDATE nilai SET nilai_angka = ?, nilai_huruf = ?, updated_at = ? WHERE id = ? AND is_final = 0'),
  finalizeKelas: db.prepare('UPDATE nilai SET is_final = 1, updated_at = ? WHERE kelas_id = ?'),
  itemsKelas: db.prepare(
    `SELECT u.nim, n.nilai_angka, n.nilai_huruf
     FROM nilai n JOIN users u ON u.id = n.mahasiswa_id
     WHERE n.kelas_id = ? ORDER BY u.nim`
  ),
};

const present = (row) => ({ ...row, is_final: Boolean(row.is_final) });

// ------------------------------------------------------------------ GET /nilai
// Mahasiswa: hanya nilai miliknya. Dosen: hanya nilai kelas yang diampu.
app.get('/nilai', requireUserRole('mahasiswa', 'dosen'), (req, res) => {
  const uid = Number(req.auth.sub); // identitas dari token terverifikasi
  const kelas = req.query.kelas_id;
  if (kelas !== undefined && typeof kelas !== 'string') return forbid(res, 'parameter kelas_id tidak valid', 400);

  if (req.auth.role === 'mahasiswa') {
    const rows = q.nilaiMahasiswa.all({ uid, kelas: kelas ?? null });
    return res.json({ role: 'mahasiswa', count: rows.length, data: rows.map(present) });
  }

  // Dosen: jika meminta kelas tertentu, kelas itu harus diampunya.
  if (kelas !== undefined) {
    const k = q.kelas.get(kelas);
    if (!k || k.dosen_id !== uid) return forbid(res, 'kelas bukan diampu dosen ini');
  }
  const rows = q.nilaiDosen.all({ uid, kelas: kelas ?? null });
  return res.json({ role: 'dosen', count: rows.length, data: rows.map(present) });
});

// ------------------------------------------------------------------ PUT /nilai/:id
// Dosen pengampu, nilai belum final, dalam jam akses.
app.put('/nilai/:id', requireUserRole('dosen'), (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return forbid(res, 'id nilai tidak valid', 400);

  const row = q.nilaiWithOwner.get(id);
  if (!row) return forbid(res, 'data nilai tidak ditemukan', 404);
  if (row.dosen_id !== Number(req.auth.sub)) return forbid(res, 'kelas bukan diampu dosen ini');
  if (row.is_final) return forbid(res, 'nilai sudah final dan tidak boleh diubah');
  if (!isWithinAccessHours()) return forbid(res, `di luar jam akses perubahan nilai (${ACCESS_HOURS.label})`);

  const angka = (req.body || {}).nilai_angka;
  if (typeof angka !== 'number' || !Number.isFinite(angka) || angka < 0 || angka > 100) {
    return forbid(res, 'nilai_angka harus berupa angka 0 sampai 100', 400);
  }

  // "AND is_final = 0" pada UPDATE menutup celah race condition dengan finalisasi yang berjalan bersamaan.
  const result = q.updateNilai.run(angka, toLetter(angka), new Date().toISOString(), id);
  if (result.changes === 0) return forbid(res, 'nilai sudah final dan tidak boleh diubah');

  const updated = db.prepare(`${SELECT_NILAI} WHERE n.id = ?`).get(id);
  return res.json({ message: 'Nilai diperbarui', data: present(updated) });
});

// ------------------------------------------------------------------ token service (client credentials)
let cachedToken = { token: null, expiresAt: 0 };

/** Mengambil token service dari POST /auth/service di gateway. Token disimpan sampai hampir kedaluwarsa. */
async function getServiceToken(force = false) {
  if (!force && cachedToken.token && Date.now() < cachedToken.expiresAt - 30_000) return cachedToken.token;
  const response = await fetch(`${GATEWAY_URL}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: SERVICE_CLIENT_ID, client_secret: SERVICE_CLIENT_SECRET }),
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error(`gagal mengambil token service (HTTP ${response.status})`);
  const data = await response.json();
  cachedToken = { token: data.access_token, expiresAt: Date.now() + data.expires_in * 1000 };
  return cachedToken.token;
}

/**
 * Memanggil Service Transkrip LEWAT GATEWAY dengan token service,
 * sehingga panggilan antar-service juga melalui PEP dan tercatat di audit log.
 */
async function syncToTranskrip(payload) {
  const send = async (token) =>
    fetch(`${GATEWAY_URL}/transkrip/sinkron`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(5000),
    });

  let response = await send(await getServiceToken());
  if (response.status === 401) response = await send(await getServiceToken(true)); // token cache mungkin sudah dicabut atau kedaluwarsa
  const body = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, body };
}

// ------------------------------------------------------------------ POST /kelas/:id/finalisasi
// Dosen pengampu dan dalam jam akses. Setelah itu memanggil sinkron transkrip.
// Operasi ini idempoten: jika sinkron sebelumnya gagal, ulangi saja finalisasinya.
app.post('/kelas/:id/finalisasi', requireUserRole('dosen'), async (req, res) => {
  const kelas = q.kelas.get(req.params.id);
  if (!kelas) return forbid(res, 'kelas tidak ditemukan', 404);
  if (kelas.dosen_id !== Number(req.auth.sub)) return forbid(res, 'kelas bukan diampu dosen ini');
  if (!isWithinAccessHours()) return forbid(res, `di luar jam akses finalisasi nilai (${ACCESS_HOURS.label})`);

  const before = q.itemsKelas.all(kelas.id);
  if (before.length === 0) return forbid(res, 'kelas belum memiliki data nilai', 409);

  q.finalizeKelas.run(new Date().toISOString(), kelas.id);

  let sync;
  try {
    sync = await syncToTranskrip({ kelas_id: kelas.id, items: q.itemsKelas.all(kelas.id) });
  } catch (err) {
    sync = { ok: false, status: 0, body: { error: err.message } };
  }

  if (!sync.ok) {
    return res.status(502).json({
      error: 'Nilai sudah final, tetapi sinkron ke transkrip gagal. Ulangi finalisasi untuk mengirim ulang.',
      kelas_id: kelas.id,
      sinkron: { status: 'gagal', http_status: sync.status, detail: sync.body },
    });
  }
  return res.json({
    message: 'Nilai kelas difinalisasi dan disinkronkan ke transkrip',
    kelas_id: kelas.id,
    jumlah_nilai: before.length,
    sinkron: { status: 'berhasil', detail: sync.body },
  });
});

app.use(notFound);
app.use(errorHandler);

app.listen(PORTS.nilai, HOST, () => {
  console.log(`[NILAI] Service Nilai aktif di http://${HOST}:${PORTS.nilai} (hanya menerima request dari gateway)`);
});
