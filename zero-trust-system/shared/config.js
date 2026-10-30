'use strict';
/**
 * Konfigurasi terpusat untuk gateway dan kedua service.
 * Semua nilai bisa diganti lewat environment variable, sehingga tidak ada
 * rahasia yang perlu di-hardcode di kode produksi.
 */
const path = require('path');

const toInt = (value, fallback) => {
  if (value === undefined || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n)) throw new Error(`Nilai env harus bilangan bulat: ${value}`);
  return n;
};

// ---------------------------------------------------------------- jaringan
const PORTS = {
  gateway: toInt(process.env.GATEWAY_PORT, 3000),
  nilai: toInt(process.env.NILAI_PORT, 3001),
  transkrip: toInt(process.env.TRANSKRIP_PORT, 3002),
};

// Default hanya mendengarkan loopback agar service tidak terbuka ke jaringan lain.
const HOST = process.env.HOST || '127.0.0.1';

const GATEWAY_URL = process.env.GATEWAY_URL || `http://127.0.0.1:${PORTS.gateway}`;
const TARGETS = {
  nilai: process.env.NILAI_URL || `http://127.0.0.1:${PORTS.nilai}`,
  transkrip: process.env.TRANSKRIP_URL || `http://127.0.0.1:${PORTS.transkrip}`,
};

// ---------------------------------------------------------------- rahasia
// Nilai default di bawah hanya untuk demo lokal. Di luar demo, wajib diganti lewat env.
const DEFAULT_SECRETS = {
  jwt: 'dev-jwt-secret-GANTI-di-produksi-minimal-32-karakter',
  gateway: 'dev-gateway-secret-GANTI-di-produksi',
  serviceClient: 'dev-service-nilai-secret-GANTI',
};

const JWT_SECRET = process.env.JWT_SECRET || DEFAULT_SECRETS.jwt;
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || DEFAULT_SECRETS.gateway;
const SERVICE_CLIENT_ID = process.env.SERVICE_CLIENT_ID || 'service-nilai';
const SERVICE_CLIENT_SECRET = process.env.SERVICE_CLIENT_SECRET || DEFAULT_SECRETS.serviceClient;

const usingDefaultSecrets =
  JWT_SECRET === DEFAULT_SECRETS.jwt ||
  GATEWAY_SECRET === DEFAULT_SECRETS.gateway ||
  SERVICE_CLIENT_SECRET === DEFAULT_SECRETS.serviceClient;

if (process.env.NODE_ENV === 'production' && usingDefaultSecrets) {
  throw new Error('NODE_ENV=production tetapi masih memakai rahasia default. Set JWT_SECRET, GATEWAY_SECRET, dan SERVICE_CLIENT_SECRET.');
}

// ---------------------------------------------------------------- token
const TOKEN = {
  accessTtl: '10m', // access token user
  serviceTtl: '5m', // token service (POST /auth/service)
  refreshTtlSeconds: 24 * 60 * 60, // refresh token berlaku 1 hari
  issuer: 'zt-gateway',
  audience: 'zt-services',
};

// ---------------------------------------------------------------- database
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'zerotrust.db');

// ---------------------------------------------------------------- jam akses
/**
 * Jam akses untuk perubahan dan finalisasi nilai (default 07:00 sampai 21:00, ujung akhir eksklusif).
 *
 * Supaya mudah didemokan ada tiga cara mengubahnya tanpa menunggu pergantian jam:
 *   1. ACCESS_START dan ACCESS_END, contoh ACCESS_START=09:00 ACCESS_END=17:00
 *   2. ACCESS_HOURS_ENABLED=false untuk mematikan pemeriksaan jam sama sekali
 *   3. MOCK_NOW=2026-10-28T23:00:00+07:00 untuk memalsukan waktu "sekarang" khusus pemeriksaan jam
 */
function parseClock(text, name) {
  const m = /^(\d{1,2}):(\d{2})$/.exec(text);
  if (!m) throw new Error(`${name} harus berformat HH:MM, diterima: ${text}`);
  const hours = Number(m[1]);
  const minutes = Number(m[2]);
  if (hours > 24 || minutes > 59 || hours * 60 + minutes > 24 * 60) {
    throw new Error(`${name} di luar rentang waktu yang valid: ${text}`);
  }
  return hours * 60 + minutes;
}

const ACCESS_START_TEXT = process.env.ACCESS_START || '07:00';
const ACCESS_END_TEXT = process.env.ACCESS_END || '21:00';

const ACCESS_HOURS = {
  enabled: process.env.ACCESS_HOURS_ENABLED !== 'false',
  start: parseClock(ACCESS_START_TEXT, 'ACCESS_START'),
  end: parseClock(ACCESS_END_TEXT, 'ACCESS_END'),
  timeZone: process.env.ACCESS_TZ || 'Asia/Jakarta',
  label: `${ACCESS_START_TEXT}-${ACCESS_END_TEXT} ${process.env.ACCESS_TZ || 'Asia/Jakarta'}`,
};

/** Waktu "sekarang" untuk pemeriksaan jam akses. Bisa dipalsukan lewat MOCK_NOW saat demo atau pengujian. */
function getNow() {
  if (process.env.MOCK_NOW) {
    const mocked = new Date(process.env.MOCK_NOW);
    if (Number.isNaN(mocked.getTime())) throw new Error(`MOCK_NOW tidak valid: ${process.env.MOCK_NOW}`);
    return mocked;
  }
  return new Date();
}
getNow(); // gagal cepat saat start kalau MOCK_NOW salah format

function minutesOfDay(date, timeZone) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone,
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  const hour = Number(parts.find((p) => p.type === 'hour').value) % 24;
  const minute = Number(parts.find((p) => p.type === 'minute').value);
  return hour * 60 + minute;
}

/** true jika `date` berada di dalam jam akses yang diizinkan. */
function isWithinAccessHours(date = getNow()) {
  if (!ACCESS_HOURS.enabled) return true;
  const t = minutesOfDay(date, ACCESS_HOURS.timeZone);
  const { start, end } = ACCESS_HOURS;
  return start <= end ? t >= start && t < end : t >= start || t < end; // mendukung rentang lewat tengah malam
}

module.exports = {
  PORTS,
  HOST,
  GATEWAY_URL,
  TARGETS,
  JWT_SECRET,
  GATEWAY_SECRET,
  SERVICE_CLIENT_ID,
  SERVICE_CLIENT_SECRET,
  usingDefaultSecrets,
  TOKEN,
  DB_PATH,
  ACCESS_HOURS,
  getNow,
  isWithinAccessHours,
};
