'use strict';
/**
 * Smoke test end-to-end. Menyalakan stack lengkap (gateway + 2 service) di port 4100-4102
 * dengan database sementara, lalu menguji skenario positif dan negatif lewat HTTP sungguhan.
 *
 *   npm test
 *
 * Tidak mengganggu stack yang sedang jalan di port 3000-3002 dan tidak menyentuh data/zerotrust.db.
 */
const { describe, test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const ROOT = path.join(__dirname, '..');
const GW = 'http://127.0.0.1:4100';
const NILAI = 'http://127.0.0.1:4101';
const TRANSKRIP = 'http://127.0.0.1:4102';

const SECRETS = {
  JWT_SECRET: 'test-jwt-secret-minimal-32-karakter-aman',
  GATEWAY_SECRET: 'test-gateway-secret',
  SERVICE_CLIENT_SECRET: 'test-service-client-secret',
};
const DB_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'zt-test-')), 'test.db');
const BASE_ENV = {
  ...process.env, ...SECRETS, DB_PATH,
  GATEWAY_PORT: '4100', NILAI_PORT: '4101', TRANSKRIP_PORT: '4102',
  NODE_ENV: 'test',
};

const DEVICES = {
  admin: 'DEV-ADMIN-01', 'dosen.a': 'DEV-DOSEN-A-01', 'dosen.b': 'DEV-DOSEN-B-01',
  mhs1: 'DEV-MHS1-01', mhs2: 'DEV-MHS2-01', mhs3: 'DEV-MHS3-01',
};
const PASS = { admin: 'Admin#123', 'dosen.a': 'Dosen#123', 'dosen.b': 'Dosen#123', mhs1: 'Mhs#123', mhs2: 'Mhs#123', mhs3: 'Mhs#123' };
const NIM = { mhs1: '2370060001', mhs2: '2370060002', mhs3: '2370060003' };

// ------------------------------------------------------------------ util
function waitForPort(port, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const socket = net.connect(port, '127.0.0.1');
      socket.once('connect', () => { socket.destroy(); resolve(); });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() > deadline) reject(new Error(`port ${port} tidak aktif`));
        else setTimeout(attempt, 150);
      });
    };
    attempt();
  });
}

async function startStack(extraEnv = {}) {
  const env = { ...BASE_ENV, ...extraEnv };
  const stdio = process.env.DEBUG_TEST ? 'inherit' : 'ignore';
  const procs = ['gateway/index.js', 'service-nilai/index.js', 'service-transkrip/index.js'].map((f) =>
    spawn(process.execPath, [path.join(ROOT, f)], { env, stdio })
  );
  await Promise.all([4100, 4101, 4102].map((p) => waitForPort(p)));
  return async () => {
    await Promise.all(procs.map((p) => new Promise((resolve) => { p.once('exit', resolve); p.kill('SIGTERM'); })));
  };
}

async function call(method, url, { token, device, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h['X-Device-ID'] = device;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const res = await fetch(url, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, json };
}

async function login(username) {
  const r = await call('POST', `${GW}/auth/login`, { device: DEVICES[username], body: { username, password: PASS[username] } });
  assert.equal(r.status, 200, `login ${username} harus berhasil: ${JSON.stringify(r.json)}`);
  return { token: r.json.access_token, refresh: r.json.refresh_token, device: DEVICES[username] };
}

const gw = (path_, who, opts = {}) => call(opts.method || 'GET', `${GW}${path_}`, { token: who.token, device: who.device, body: opts.body });

const forgeToken = (claims, secret, options) =>
  jwt.sign(claims, secret, { algorithm: 'HS256', issuer: 'zt-gateway', audience: 'zt-services', ...options });

// ------------------------------------------------------------------ FASE A: jam akses terbuka (10:00 WIB)
describe('Fase A: dalam jam akses', () => {
  let stop;
  const S = {}; // sesi login per user
  const nilaiId = {}; // id nilai yang dibutuhkan

  before(async () => {
    execFileSync(process.execPath, [path.join(ROOT, 'shared/seed.js')], { env: BASE_ENV, stdio: 'ignore' });
    stop = await startStack({ MOCK_NOW: '2026-10-28T10:00:00+07:00' });
  });
  after(async () => { if (stop) await stop(); });

  test('login: kredensial salah 401, device kosong atau milik orang lain 403', async () => {
    let r = await call('POST', `${GW}/auth/login`, { device: DEVICES.mhs1, body: { username: 'mhs1', password: 'salah' } });
    assert.equal(r.status, 401);
    r = await call('POST', `${GW}/auth/login`, { body: { username: 'mhs1', password: PASS.mhs1 } });
    assert.equal(r.status, 403);
    r = await call('POST', `${GW}/auth/login`, { device: DEVICES.mhs2, body: { username: 'mhs1', password: PASS.mhs1 } });
    assert.equal(r.status, 403);
  });

  test('login berhasil untuk semua user', async () => {
    for (const u of Object.keys(DEVICES)) S[u] = await login(u);
    const claims = jwt.decode(S.mhs1.token);
    assert.equal(claims.role, 'mahasiswa');
    assert.ok(claims.sub);
    assert.equal(claims.exp - claims.iat, 600, 'access token berlaku 10 menit');
  });

  test('token: tanpa token, sampah, kedaluwarsa, secret salah, dan alg none semuanya 401', async () => {
    let r = await call('GET', `${GW}/nilai`, { device: DEVICES.mhs1 });
    assert.equal(r.status, 401);
    r = await call('GET', `${GW}/nilai`, { token: 'bukan.token.sama-sekali', device: DEVICES.mhs1 });
    assert.equal(r.status, 401);

    const base = { role: 'dosen', token_use: 'access', sid: 1, dev: DEVICES['dosen.a'] };
    const expired = forgeToken(base, SECRETS.JWT_SECRET, { subject: '2', expiresIn: -10 });
    r = await call('GET', `${GW}/nilai`, { token: expired, device: DEVICES['dosen.a'] });
    assert.equal(r.status, 401);
    assert.match(r.json.reason, /kedaluwarsa/);

    const wrongSecret = forgeToken(base, 'secret-palsu-penyerang', { subject: '2', expiresIn: '10m' });
    r = await call('GET', `${GW}/nilai`, { token: wrongSecret, device: DEVICES['dosen.a'] });
    assert.equal(r.status, 401);

    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const algNone = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ ...base, sub: '2', iss: 'zt-gateway', aud: 'zt-services', exp: 9999999999 })}.`;
    r = await call('GET', `${GW}/nilai`, { token: algNone, device: DEVICES['dosen.a'] });
    assert.equal(r.status, 401);
  });

  test('device: header tidak ada atau device user lain ditolak 403', async () => {
    let r = await call('GET', `${GW}/nilai`, { token: S.mhs1.token });
    assert.equal(r.status, 403);
    r = await call('GET', `${GW}/nilai`, { token: S.mhs1.token, device: DEVICES.mhs2 });
    assert.equal(r.status, 403);
    r = await call('GET', `${GW}/nilai`, { token: S.mhs1.token, device: 'DEV-TIDAK-ADA' });
    assert.equal(r.status, 403);
  });

  test('GET /nilai: setiap role hanya melihat data yang menjadi haknya', async () => {
    let r = await gw('/nilai', S.mhs1);
    assert.equal(r.status, 200);
    assert.equal(r.json.count, 2);
    assert.ok(r.json.data.every((x) => x.nim === NIM.mhs1));

    r = await gw('/nilai', S.mhs3);
    assert.equal(r.json.count, 1);
    assert.ok(r.json.data.every((x) => x.nim === NIM.mhs3));

    r = await gw('/nilai', S['dosen.a']);
    assert.equal(r.json.count, 3);
    assert.ok(r.json.data.every((x) => x.kelas_id === 'K1'));
    for (const row of r.json.data) if (row.nim === NIM.mhs1) nilaiId.k1mhs1 = row.id;

    r = await gw('/nilai', S['dosen.b']);
    assert.equal(r.json.count, 2);
    assert.ok(r.json.data.every((x) => x.kelas_id === 'K2'));
    for (const row of r.json.data) if (row.nim === NIM.mhs1) nilaiId.k2mhs1 = row.id;

    r = await gw('/nilai', S.admin);
    assert.equal(r.status, 403, 'admin tidak berhak membaca nilai');

    r = await gw('/nilai?kelas_id=K2', S['dosen.a']);
    assert.equal(r.status, 403, 'dosen A tidak boleh meminta kelas dosen B');
    r = await gw('/nilai?kelas_id=K1', S['dosen.a']);
    assert.equal(r.status, 200);
  });

  test('PUT /nilai/:id: hanya dosen pengampu', async () => {
    let r = await gw(`/nilai/${nilaiId.k1mhs1}`, S.mhs1, { method: 'PUT', body: { nilai_angka: 100 } });
    assert.equal(r.status, 403, 'mahasiswa tidak boleh mengubah nilai');
    r = await gw(`/nilai/${nilaiId.k1mhs1}`, S['dosen.b'], { method: 'PUT', body: { nilai_angka: 100 } });
    assert.equal(r.status, 403, 'dosen B bukan pengampu K1');
    r = await gw(`/nilai/${nilaiId.k1mhs1}`, S.admin, { method: 'PUT', body: { nilai_angka: 100 } });
    assert.equal(r.status, 403);
    r = await gw('/nilai/999999', S['dosen.a'], { method: 'PUT', body: { nilai_angka: 80 } });
    assert.equal(r.status, 404);
    r = await gw(`/nilai/${nilaiId.k1mhs1}`, S['dosen.a'], { method: 'PUT', body: { nilai_angka: 150 } });
    assert.equal(r.status, 400, 'nilai di luar 0-100 ditolak');
    r = await gw(`/nilai/${nilaiId.k1mhs1}`, S['dosen.a'], { method: 'PUT', body: { nilai_angka: 95 } });
    assert.equal(r.status, 200);
    assert.equal(r.json.data.nilai_angka, 95);
    assert.equal(r.json.data.nilai_huruf, 'A');
  });

  test('GET /transkrip/:nim: mahasiswa hanya NIM sendiri, admin semua', async () => {
    let r = await gw(`/transkrip/${NIM.mhs1}`, S.mhs1);
    assert.equal(r.status, 200);
    assert.equal(r.json.count, 0, 'belum ada yang disinkronkan');
    r = await gw(`/transkrip/${NIM.mhs2}`, S.mhs1);
    assert.equal(r.status, 403);
    r = await gw(`/transkrip/${NIM.mhs2}`, S.admin);
    assert.equal(r.status, 200);
    r = await gw('/transkrip/9999999999', S.admin);
    assert.equal(r.status, 404);
    r = await gw(`/transkrip/${NIM.mhs1}`, S['dosen.a']);
    assert.equal(r.status, 403, 'dosen tidak berhak membaca transkrip');
  });

  test('POST /transkrip/sinkron: token user mana pun ditolak 403', async () => {
    const payload = { kelas_id: 'K1', items: [{ nim: NIM.mhs1, nilai_angka: 95, nilai_huruf: 'A' }] };
    for (const u of ['admin', 'dosen.a', 'mhs1']) {
      const r = await gw('/transkrip/sinkron', S[u], { method: 'POST', body: payload });
      assert.equal(r.status, 403, `token ${u} harus ditolak`);
    }
  });

  test('bypass gateway: service tidak bisa diakses langsung', async () => {
    // Tanpa X-Gateway-Secret
    let r = await call('GET', `${NILAI}/nilai`, { token: S['dosen.a'].token });
    assert.equal(r.status, 403);
    r = await call('GET', `${TRANSKRIP}/transkrip/${NIM.mhs1}`, { token: S.admin.token });
    assert.equal(r.status, 403);
    // Secret benar tetapi tanpa token
    r = await call('GET', `${NILAI}/nilai`, { headers: { 'X-Gateway-Secret': SECRETS.GATEWAY_SECRET } });
    assert.equal(r.status, 401);
    // Secret benar tetapi token dipalsukan
    const fake = forgeToken({ role: 'admin', token_use: 'access', sid: 1, dev: 'x' }, 'secret-palsu', { subject: '1', expiresIn: '10m' });
    r = await call('GET', `${TRANSKRIP}/transkrip/${NIM.mhs1}`, { token: fake, headers: { 'X-Gateway-Secret': SECRETS.GATEWAY_SECRET } });
    assert.equal(r.status, 401);
    // Secret salah
    r = await call('GET', `${NILAI}/nilai`, { token: S['dosen.a'].token, headers: { 'X-Gateway-Secret': 'tebakan' } });
    assert.equal(r.status, 403);
    // Secret benar + token user valid, tetapi ke endpoint sinkron: service tetap menolak berdasarkan role
    r = await call('POST', `${TRANSKRIP}/transkrip/sinkron`, {
      token: S.admin.token, headers: { 'X-Gateway-Secret': SECRETS.GATEWAY_SECRET },
      body: { kelas_id: 'K1', items: [{ nim: NIM.mhs1, nilai_angka: 95, nilai_huruf: 'A' }] },
    });
    assert.equal(r.status, 403);
    // Secret benar + token dosen B valid langsung ke service: data tetap disaring oleh service
    r = await call('GET', `${NILAI}/nilai`, { token: S['dosen.b'].token, headers: { 'X-Gateway-Secret': SECRETS.GATEWAY_SECRET } });
    assert.equal(r.status, 200);
    assert.ok(r.json.data.every((x) => x.kelas_id === 'K2'));
  });

  test('POST /auth/service: secret salah 401, secret benar menghasilkan token role service 5 menit', async () => {
    let r = await call('POST', `${GW}/auth/service`, { body: { client_id: 'service-nilai', client_secret: 'salah' } });
    assert.equal(r.status, 401);
    r = await call('POST', `${GW}/auth/service`, { body: { client_id: 'service-nilai', client_secret: SECRETS.SERVICE_CLIENT_SECRET } });
    assert.equal(r.status, 200);
    const claims = jwt.decode(r.json.access_token);
    assert.equal(claims.role, 'service');
    assert.equal(claims.exp - claims.iat, 300);
    S.service = { token: r.json.access_token };

    r = await call('GET', `${GW}/nilai`, { token: S.service.token });
    assert.equal(r.status, 403, 'token service tidak boleh membaca nilai');
    r = await call('POST', `${GW}/transkrip/sinkron`, {
      token: S.service.token,
      body: { kelas_id: 'K2', items: [{ nim: NIM.mhs1, nilai_angka: 78, nilai_huruf: 'B+' }] },
    });
    assert.equal(r.status, 409, 'token service lolos kebijakan akses, tetapi K2 belum final sehingga isi ditolak');
  });

  test('POST /kelas/:id/finalisasi: hanya dosen pengampu, lalu data masuk transkrip', async () => {
    let r = await gw('/kelas/K1/finalisasi', S['dosen.b'], { method: 'POST' });
    assert.equal(r.status, 403, 'dosen B bukan pengampu K1');
    r = await gw('/kelas/K1/finalisasi', S.mhs1, { method: 'POST' });
    assert.equal(r.status, 403);
    r = await gw('/kelas/K9/finalisasi', S['dosen.a'], { method: 'POST' });
    assert.equal(r.status, 404);

    r = await gw('/kelas/K1/finalisasi', S['dosen.a'], { method: 'POST' });
    assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.equal(r.json.sinkron.status, 'berhasil');
    assert.equal(r.json.jumlah_nilai, 3);

    r = await gw(`/transkrip/${NIM.mhs1}`, S.mhs1);
    assert.equal(r.json.count, 1);
    assert.equal(r.json.transkrip[0].kelas_id, 'K1');
    assert.equal(r.json.transkrip[0].nilai_angka, 95, 'nilai hasil PUT sebelumnya yang terkirim ke transkrip');

    r = await gw(`/nilai/${nilaiId.k1mhs1}`, S['dosen.a'], { method: 'PUT', body: { nilai_angka: 10 } });
    assert.equal(r.status, 403, 'nilai final tidak boleh diubah');
    assert.match(r.json.reason, /final/);
  });

  test('refresh dan logout: logout mematikan sesi, termasuk access token yang masih berlaku', async () => {
    const s = await login('mhs3');
    let r = await call('POST', `${GW}/auth/refresh`, { device: 'DEV-LAIN', body: { refresh_token: s.refresh } });
    assert.equal(r.status, 403, 'refresh dari device lain ditolak');
    r = await call('POST', `${GW}/auth/refresh`, { device: s.device, body: { refresh_token: 'ngawur' } });
    assert.equal(r.status, 401);
    r = await call('POST', `${GW}/auth/refresh`, { device: s.device, body: { refresh_token: s.refresh } });
    assert.equal(r.status, 200);
    const renewed = { token: r.json.access_token, device: s.device };
    r = await gw('/nilai', renewed);
    assert.equal(r.status, 200);

    r = await call('POST', `${GW}/auth/logout`, { body: { refresh_token: s.refresh } });
    assert.equal(r.status, 200);
    r = await call('POST', `${GW}/auth/logout`, { body: { refresh_token: s.refresh } });
    assert.equal(r.status, 401, 'refresh token yang sudah dicabut tidak valid lagi');
    r = await call('POST', `${GW}/auth/refresh`, { device: s.device, body: { refresh_token: s.refresh } });
    assert.equal(r.status, 401);
    r = await gw('/nilai', s);
    assert.equal(r.status, 401, 'access token lama ikut mati karena sesinya dicabut');
    r = await gw('/nilai', renewed);
    assert.equal(r.status, 401);
  });

  test('default deny: endpoint tanpa aturan ditolak', async () => {
    let r = await gw('/admin/rahasia', S.admin);
    assert.equal(r.status, 403);
    r = await gw('/NILAI', S.mhs1);
    assert.equal(r.status, 403, 'variasi huruf besar tidak boleh menghindari kebijakan');
    r = await gw('/nilai/%31', S['dosen.a'], { method: 'PUT', body: { nilai_angka: 1 } });
    assert.equal(r.status, 403, 'path ter-encode tidak boleh menghindari kebijakan');
  });

  test('audit log mencatat ALLOW dan DENY lengkap dengan alasan', () => {
    const db = new Database(DB_PATH, { readonly: true });
    const rows = db.prepare('SELECT * FROM audit_logs').all();
    db.close();
    assert.ok(rows.length > 30);
    assert.ok(rows.some((x) => x.decision === 'ALLOW'));
    assert.ok(rows.some((x) => x.decision === 'DENY'));
    for (const col of ['ts', 'subject', 'endpoint', 'device', 'decision', 'reason']) {
      assert.ok(rows.every((x) => x[col] && String(x[col]).length > 0), `kolom ${col} harus selalu terisi`);
    }
    assert.ok(rows.some((x) => x.subject.startsWith('service:') && x.endpoint === '/transkrip/sinkron' && x.decision === 'ALLOW'));
    assert.ok(rows.some((x) => /device tidak terdaftar/.test(x.reason)));
    assert.ok(rows.some((x) => /bukan diampu/.test(x.reason)));
  });
});

// ------------------------------------------------------------------ FASE B: di luar jam akses (23:00 WIB)
describe('Fase B: di luar jam akses', () => {
  let stop;
  before(async () => { stop = await startStack({ MOCK_NOW: '2026-10-28T23:00:00+07:00' }); });
  after(async () => { if (stop) await stop(); });

  test('ubah dan finalisasi nilai ditolak, baca tetap boleh, dan service ikut menolak', async () => {
    const dosenB = await login('dosen.b');
    let r = await gw('/nilai', dosenB);
    assert.equal(r.status, 200, 'membaca nilai tidak dibatasi jam');
    const id = r.json.data[0].id;

    r = await gw(`/nilai/${id}`, dosenB, { method: 'PUT', body: { nilai_angka: 70 } });
    assert.equal(r.status, 403);
    assert.match(r.json.reason, /jam akses/);

    r = await gw('/kelas/K2/finalisasi', dosenB, { method: 'POST' });
    assert.equal(r.status, 403);
    assert.match(r.json.reason, /jam akses/);

    // Lewati gateway (anggap bocor): service tetap menolak karena memeriksa jam akses sendiri.
    r = await call('PUT', `${NILAI}/nilai/${id}`, {
      token: dosenB.token, headers: { 'X-Gateway-Secret': SECRETS.GATEWAY_SECRET }, body: { nilai_angka: 70 },
    });
    assert.equal(r.status, 403);
    assert.match(r.json.reason, /jam akses/);

    const db = new Database(DB_PATH, { readonly: true });
    const denied = db.prepare("SELECT COUNT(*) AS n FROM audit_logs WHERE decision='DENY' AND reason LIKE '%jam akses%'").get().n;
    db.close();
    assert.ok(denied >= 2);
  });
});
