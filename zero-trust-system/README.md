# Zero Trust Security: Sistem Nilai dengan API Gateway

Tugas Praktikum Individu, Keamanan Informasi (KP70065004), Informatika Universitas Siliwangi.

Proyek ini menerapkan prinsip **never trust, always verify**, **least privilege**, dan **assume breach** langsung di level aplikasi. Sebuah API gateway berperan sebagai *Policy Enforcement Point* (PEP) yang terpisah dari service, mengikuti model logis NIST SP 800-207.

## Arsitektur

```
                       +------------------------------------------+
  Postman / curl ----> |  API GATEWAY :3000                       |
                       |  PEP  : periksa token, device, audit,    |
                       |         teruskan + X-Gateway-Secret      |
                       |  PE/PA: login, refresh, logout, token    |
                       |         service, policy.js (allow/deny)  |
                       +--------+-----------------------+---------+
                                |                       |
                 X-Gateway-Secret + JWT          X-Gateway-Secret + JWT
                                v                       v
                    +-------------------+     +----------------------+
                    | Service Nilai     |     | Service Transkrip    |
                    | :3001             |     | :3002                |
                    +---------+---------+     +----------------------+
                              |  POST /transkrip/sinkron (token service,
                              |  lewat gateway lagi, bukan langsung)
                              +--------------------> kembali ke gateway

          Satu database SQLite bersama (users, kelas, nilai, transkrip,
          devices, refresh_tokens, audit_logs)
```

| Komponen | Peran NIST SP 800-207 | File |
|---|---|---|
| API Gateway | PEP | `gateway/index.js` |
| Policy Engine / Administrator | PE/PA | `gateway/policy.js`, `gateway/auth.js` |
| Service Nilai | Resource | `service-nilai/index.js` |
| Service Transkrip | Resource | `service-transkrip/index.js` |
| Database | Resource | `shared/database.js` |
| Audit log | Data source | `gateway/auditLogger.js` (tabel `audit_logs`) |

## Prasyarat

- Node.js 18 atau lebih baru (diuji sintaksnya di Node 22)
- npm
- `better-sqlite3` memakai binary prebuilt. Jika `npm install` gagal membangunnya di versi Node yang sangat baru, jalankan `npm install better-sqlite3@latest`

## Cara menjalankan

```bash
npm install
npm run seed      # membuat data awal (menghapus data lama)
npm start         # menjalankan gateway, Service Nilai, dan Service Transkrip sekaligus
```

Alternatif jika ingin tiga terminal terpisah (enak untuk video demo):

```bash
npm run start:gateway
npm run start:nilai
npm run start:transkrip
```

Hentikan semua service sebelum menjalankan `npm run seed` lagi.

Database dibuat otomatis di `data/zerotrust.db`.

## Daftar akun dan device ID data awal

| Username | Password | Role | NIM | X-Device-ID |
|---|---|---|---|---|
| `admin` | `Admin#123` | admin | - | `DEV-ADMIN-01` |
| `dosen.a` | `Dosen#123` | dosen (mengampu K1) | - | `DEV-DOSEN-A-01` |
| `dosen.b` | `Dosen#123` | dosen (mengampu K2) | - | `DEV-DOSEN-B-01` |
| `mhs1` | `Mhs#123` | mahasiswa | 2370060001 | `DEV-MHS1-01` |
| `mhs2` | `Mhs#123` | mahasiswa | 2370060002 | `DEV-MHS2-01` |
| `mhs3` | `Mhs#123` | mahasiswa | 2370060003 | `DEV-MHS3-01` |

Kredensial Service Nilai: `client_id = service-nilai`, `client_secret = dev-service-nilai-secret-GANTI`.

Kelas: **K1** Keamanan Informasi (dosen A, nilai mhs1, mhs2, mhs3) dan **K2** Pemrograman Web (dosen B, nilai mhs1, mhs2).

## Pemetaan kebutuhan ke kode (untuk video demo)

Tabel ini membantu menunjukkan bagian kode yang menangani tiap kebutuhan.

| Kebutuhan | Penanganan | Lokasi |
|---|---|---|
| Access token JWT 10 menit berisi `sub` dan `role` | Diterbitkan saat login | `signAccessToken` di `shared/security.js`, dipakai `POST /login` di `gateway/auth.js` |
| Refresh token 1 hari, disimpan di DB, bisa dicabut | Token acak, yang disimpan hash SHA-256-nya | `POST /login`, `/refresh`, `/logout` di `gateway/auth.js`, tabel `refresh_tokens` |
| Logout mencabut refresh token | Kolom `revoked` diubah menjadi 1 | `POST /logout` di `gateway/auth.js` |
| Token service 5 menit, `role: service` | Client credentials | `POST /service` di `gateway/auth.js`, `signServiceToken` di `shared/security.js` |
| Gateway menambahkan `X-Gateway-Secret` | Hook `proxyReq` pada proxy | `makeProxy` di `gateway/index.js` |
| Service menolak request tanpa secret | Lapis 1 guard, perbandingan waktu konstan | `zeroTrustGuard` di `shared/guard.js` |
| Service verifikasi ulang JWT walau secret cocok | Lapis 2 guard (tanda tangan, masa berlaku, issuer, audience, algoritma HS256) | `zeroTrustGuard` dan `verifyToken` |
| Wajib token valid untuk selain `/auth/*` | Langkah (a) PEP | `enforce` di `gateway/index.js` |
| Device terdaftar (`X-Device-ID`) | Langkah (b) PEP, juga saat login dan refresh | `enforce`, `POST /login` |
| Kebijakan akses per endpoint, ABAC dari database | Tabel aturan, default deny | `RULES` dan `evaluate` di `gateway/policy.js` |
| Kepemilikan data (NIM, kelas diampu, status final) | Dibaca dari DB, bukan dari token | `gateway/policy.js` dan query di tiap service |
| Jam akses ubah dan finalisasi nilai | Bisa diatur lewat env | `isWithinAccessHours` di `shared/config.js`, dipakai `policy.js` dan Service Nilai |
| Panggilan antar-service lewat gateway | Service Nilai memakai token service | `syncToTranskrip` di `service-nilai/index.js` |
| Hanya token service boleh `POST /transkrip/sinkron` | Aturan policy dan cek ulang di service | `gateway/policy.js` dan `service-transkrip/index.js` |
| Audit log setiap keputusan | ALLOW dan DENY, termasuk `/auth/*` | `logDecision` di `gateway/auditLogger.js` |

## Konfigurasi lewat environment variable

| Variabel | Default | Fungsi |
|---|---|---|
| `JWT_SECRET` | nilai dev | Kunci tanda tangan JWT |
| `GATEWAY_SECRET` | nilai dev | Isi header `X-Gateway-Secret` |
| `SERVICE_CLIENT_SECRET` | nilai dev | Secret Service Nilai (dipakai seed dan service) |
| `ACCESS_START`, `ACCESS_END` | `07:00`, `21:00` | Jam akses ubah dan finalisasi nilai (akhir tidak termasuk) |
| `ACCESS_TZ` | `Asia/Jakarta` | Zona waktu jam akses |
| `ACCESS_HOURS_ENABLED` | `true` | `false` mematikan pemeriksaan jam |
| `MOCK_NOW` | kosong | Memalsukan waktu "sekarang" untuk pemeriksaan jam, contoh `2026-10-28T23:00:00+07:00` |
| `GATEWAY_PORT`, `NILAI_PORT`, `TRANSKRIP_PORT` | 3000, 3001, 3002 | Port |
| `DB_PATH` | `data/zerotrust.db` | Lokasi database |

Rahasia default hanya untuk demo lokal. Gateway menampilkan peringatan jika masih memakainya, dan proses menolak start jika `NODE_ENV=production`.

Contoh mendemokan jam akses tanpa menunggu malam:

```bash
MOCK_NOW=2026-10-28T23:00:00+07:00 npm start
```

## Skenario uji dengan curl

Perintah ini ditulis untuk bash. Pengguna Windows bisa memakai Git Bash atau memasukkan request yang sama ke Postman.

```bash
GW=http://127.0.0.1:3000
tok() { sed -E 's/.*"access_token":"([^"]+)".*/\1/'; }

# 1. Login (device wajib terdaftar)
MHS1=$(curl -s -X POST $GW/auth/login -H 'Content-Type: application/json' -H 'X-Device-ID: DEV-MHS1-01' \
  -d '{"username":"mhs1","password":"Mhs#123"}' | tok)
DOSEN_A=$(curl -s -X POST $GW/auth/login -H 'Content-Type: application/json' -H 'X-Device-ID: DEV-DOSEN-A-01' \
  -d '{"username":"dosen.a","password":"Dosen#123"}' | tok)
ADMIN=$(curl -s -X POST $GW/auth/login -H 'Content-Type: application/json' -H 'X-Device-ID: DEV-ADMIN-01' \
  -d '{"username":"admin","password":"Admin#123"}' | tok)

# 2. Mahasiswa hanya melihat nilai miliknya
curl -s $GW/nilai -H "Authorization: Bearer $MHS1" -H 'X-Device-ID: DEV-MHS1-01'

# 3. Dosen A melihat nilai kelasnya, lalu mengubah satu nilai (ganti 1 dengan id dari langkah ini)
curl -s $GW/nilai -H "Authorization: Bearer $DOSEN_A" -H 'X-Device-ID: DEV-DOSEN-A-01'
curl -s -X PUT $GW/nilai/1 -H "Authorization: Bearer $DOSEN_A" -H 'X-Device-ID: DEV-DOSEN-A-01' \
  -H 'Content-Type: application/json' -d '{"nilai_angka": 95}'

# 4. Finalisasi kelas K1, otomatis disinkronkan ke transkrip lewat gateway
curl -s -X POST $GW/kelas/K1/finalisasi -H "Authorization: Bearer $DOSEN_A" -H 'X-Device-ID: DEV-DOSEN-A-01'

# 5. Mahasiswa membaca transkrip sendiri, admin membaca transkrip siapa saja
curl -s $GW/transkrip/2370060001 -H "Authorization: Bearer $MHS1" -H 'X-Device-ID: DEV-MHS1-01'
curl -s $GW/transkrip/2370060002 -H "Authorization: Bearer $ADMIN" -H 'X-Device-ID: DEV-ADMIN-01'
```

### Skenario yang harus ditolak

```bash
# Mahasiswa membaca transkrip orang lain -> 403
curl -s -i $GW/transkrip/2370060002 -H "Authorization: Bearer $MHS1" -H 'X-Device-ID: DEV-MHS1-01'

# Device tidak terdaftar -> 403
curl -s -i $GW/nilai -H "Authorization: Bearer $MHS1" -H 'X-Device-ID: DEV-ASING'

# Tanpa token -> 401
curl -s -i $GW/nilai -H 'X-Device-ID: DEV-MHS1-01'

# Token user memanggil sinkron -> 403
curl -s -i -X POST $GW/transkrip/sinkron -H "Authorization: Bearer $ADMIN" -H 'X-Device-ID: DEV-ADMIN-01' \
  -H 'Content-Type: application/json' -d '{"kelas_id":"K1","items":[]}'

# Akses langsung ke service tanpa gateway -> 403
curl -s -i http://127.0.0.1:3001/nilai -H "Authorization: Bearer $MHS1"

# Nilai yang sudah final diubah lagi -> 403
curl -s -i -X PUT $GW/nilai/1 -H "Authorization: Bearer $DOSEN_A" -H 'X-Device-ID: DEV-DOSEN-A-01' \
  -H 'Content-Type: application/json' -d '{"nilai_angka": 10}'
```

### Melihat audit log

```bash
node -e "const {db}=require('./shared/database');console.table(db.prepare('SELECT ts,subject,method,endpoint,device,decision,reason FROM audit_logs ORDER BY id DESC LIMIT 20').all())"
```

## Pengujian otomatis

```bash
npm test
```

Test menyalakan stack sendiri di port 4100 sampai 4102 dengan database sementara, jadi aman dijalankan walau stack utama sedang hidup. Cakupannya: login, token palsu dan kedaluwarsa, `alg: none`, device, ABAC tiap endpoint, bypass gateway, token service, finalisasi sampai masuk transkrip, refresh dan logout, default deny, audit log, dan jam akses (fase terpisah dengan waktu 23:00).

## Keputusan desain yang perlu dijelaskan saat presentasi

- **Dua lapis pemeriksaan.** Gateway memutuskan, tetapi service tetap memeriksa gateway secret, JWT, role, kepemilikan data, status final, dan jam akses. Ini wujud *assume breach*: kebocoran satu lapis tidak otomatis membuka data.
- **Atribut dibaca dari database.** Token hanya membawa identitas dan role. NIM, kelas yang diampu, dan status final dibaca dari DB sehingga keputusan selalu memakai data terbaru.
- **Sesi bisa dicabut seketika.** Access token membawa `sid`. Gateway memeriksa sesi masih aktif, jadi logout langsung mematikan access token yang masih berlaku. Tanpa ini, token JWT stateless tetap hidup sampai 10 menit setelah logout.
- **Token terikat device.** Access token dan refresh token hanya berlaku dari device yang dipakai saat login. Syarat ini lebih ketat dari soal. Endpoint `/auth/refresh` karenanya wajib menyertakan `X-Device-ID`.
- **Fail closed.** Jika audit gagal ditulis atau terjadi error internal, request ditolak dan tidak diteruskan.
- **Default deny.** Path atau method tanpa aturan ditolak. Variasi huruf besar atau path ter-encode tidak bisa menghindari kebijakan karena proxy hanya meneruskan request yang cocok dengan aturan.
- **Finalisasi idempoten.** Jika sinkron ke transkrip gagal, respons 502 dan finalisasi bisa diulang untuk mengirim ulang.
- **Pesan login seragam.** User tidak ada dan password salah menghasilkan respons yang sama, dan waktu responsnya disamakan dengan hash palsu.
- **Alamat `127.0.0.1`.** Service memakai `127.0.0.1` dan bukan `localhost`. Pada Node versi baru `localhost` bisa di-resolve ke IPv6 sehingga koneksi ke server yang hanya mendengarkan IPv4 gagal. Nilainya bisa diganti lewat `GATEWAY_URL`.

## Keterbatasan

- JWT memakai kunci simetris (HS256) yang dibagi ke gateway dan service. Untuk produksi yang lebih ketat, kunci asimetris (RS256 atau EdDSA) membuat service cukup memegang kunci publik.
- `X-Gateway-Secret` adalah rahasia bersama. Di produksi, mutual TLS antara gateway dan service lebih kuat.
- Tidak ada pembatasan percobaan login (rate limiting).
- Komunikasi berjalan di HTTP lokal tanpa TLS karena semuanya satu komputer.

## Referensi

- Rose, S., Borchert, O., Mitchell, S., dan Connelly, S. (2020). *Zero Trust Architecture* (NIST Special Publication 800-207). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-207
