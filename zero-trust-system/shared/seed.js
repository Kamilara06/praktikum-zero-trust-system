'use strict';
/**
 * Seeder database. Menjalankan ulang script ini MENGHAPUS semua data lama lalu mengisi ulang.
 * Hentikan gateway dan service sebelum seed ulang.
 *
 *   npm run seed
 *
 * Data: 1 admin, 2 dosen, 3 mahasiswa, 2 kelas (beda dosen), nilai, 1 device per user,
 * dan 1 kredensial client untuk Service Nilai.
 */
const bcrypt = require('bcryptjs');
const { db, initSchema, dropSchema } = require('./database');
const { SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET, usingDefaultSecrets } = require('./config');
const { toLetter } = require('./grade');

const PASSWORDS = { admin: 'Admin#123', dosen: 'Dosen#123', mahasiswa: 'Mhs#123' };

const USERS = [
  { username: 'admin', nama: 'Admin Prodi Informatika', role: 'admin', nim: null, device: 'DEV-ADMIN-01' },
  { username: 'dosen.a', nama: 'Dosen A', role: 'dosen', nim: null, device: 'DEV-DOSEN-A-01' },
  { username: 'dosen.b', nama: 'Dosen B', role: 'dosen', nim: null, device: 'DEV-DOSEN-B-01' },
  { username: 'mhs1', nama: 'Mahasiswa Satu', role: 'mahasiswa', nim: '2370060001', device: 'DEV-MHS1-01' },
  { username: 'mhs2', nama: 'Mahasiswa Dua', role: 'mahasiswa', nim: '2370060002', device: 'DEV-MHS2-01' },
  { username: 'mhs3', nama: 'Mahasiswa Tiga', role: 'mahasiswa', nim: '2370060003', device: 'DEV-MHS3-01' },
];

const KELAS = [
  { id: 'K1', nama_mk: 'Keamanan Informasi', dosen: 'dosen.a' },
  { id: 'K2', nama_mk: 'Pemrograman Web', dosen: 'dosen.b' },
];

const NILAI = [
  { kelas: 'K1', mhs: 'mhs1', angka: 85 },
  { kelas: 'K1', mhs: 'mhs2', angka: 72.5 },
  { kelas: 'K1', mhs: 'mhs3', angka: 90 },
  { kelas: 'K2', mhs: 'mhs1', angka: 78 },
  { kelas: 'K2', mhs: 'mhs2', angka: 88 },
];

function seed() {
  dropSchema();
  initSchema();

  // Hash dihitung di luar transaksi karena bcrypt cukup lambat (sengaja, untuk menyulitkan brute force).
  const hashed = USERS.map((u) => ({ ...u, hash: bcrypt.hashSync(PASSWORDS[u.role], 10) }));
  const serviceHash = bcrypt.hashSync(SERVICE_CLIENT_SECRET, 10);
  const now = new Date().toISOString();

  const insertUser = db.prepare('INSERT INTO users (username, password_hash, nama, role, nim) VALUES (?, ?, ?, ?, ?)');
  const insertDevice = db.prepare('INSERT INTO devices (user_id, device_id) VALUES (?, ?)');
  const insertKelas = db.prepare('INSERT INTO kelas (id, nama_mk, dosen_id) VALUES (?, ?, ?)');
  const insertNilai = db.prepare(
    'INSERT INTO nilai (kelas_id, mahasiswa_id, nilai_angka, nilai_huruf, is_final, updated_at) VALUES (?, ?, ?, ?, 0, ?)'
  );
  const insertClient = db.prepare('INSERT INTO service_clients (client_id, secret_hash, nama) VALUES (?, ?, ?)');

  db.transaction(() => {
    const idOf = {};
    for (const u of hashed) {
      const info = insertUser.run(u.username, u.hash, u.nama, u.role, u.nim);
      idOf[u.username] = Number(info.lastInsertRowid);
      insertDevice.run(idOf[u.username], u.device);
    }
    for (const k of KELAS) insertKelas.run(k.id, k.nama_mk, idOf[k.dosen]);
    for (const n of NILAI) insertNilai.run(n.kelas, idOf[n.mhs], n.angka, toLetter(n.angka), now);
    insertClient.run(SERVICE_CLIENT_ID, serviceHash, 'Service Nilai');
  })();

  console.log('Seed selesai.\n');
  console.table(
    USERS.map((u) => ({ username: u.username, password: PASSWORDS[u.role], role: u.role, nim: u.nim || '-', 'X-Device-ID': u.device }))
  );
  console.log(`Service client  : ${SERVICE_CLIENT_ID}`);
  console.log(`Service secret  : ${usingDefaultSecrets ? SERVICE_CLIENT_SECRET : '(dari env SERVICE_CLIENT_SECRET)'}`);
}

if (require.main === module) seed();

module.exports = { seed, USERS, KELAS, NILAI, PASSWORDS };
