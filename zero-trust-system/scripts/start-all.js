'use strict';
/**
 * Menjalankan gateway, Service Nilai, dan Service Transkrip sekaligus dalam satu terminal.
 * Output tiap proses diberi awalan nama. Ctrl+C menghentikan semuanya.
 *
 *   npm start
 */
const { spawn } = require('child_process');
const path = require('path');
const readline = require('readline');

const ROOT = path.join(__dirname, '..');
const SERVICES = [
  ['gateway', 'gateway/index.js'],
  ['nilai', 'service-nilai/index.js'],
  ['transkrip', 'service-transkrip/index.js'],
];

const children = [];
let stopping = false;

function stopAll(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill('SIGTERM');
  setTimeout(() => process.exit(code), 300);
}

for (const [name, file] of SERVICES) {
  const child = spawn(process.execPath, [path.join(ROOT, file)], { env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
  children.push(child);
  const label = name.padEnd(9);
  readline.createInterface({ input: child.stdout }).on('line', (line) => console.log(`${label}| ${line}`));
  readline.createInterface({ input: child.stderr }).on('line', (line) => console.error(`${label}| ${line}`));
  child.on('exit', (code) => {
    if (stopping) return;
    console.error(`${label}| berhenti dengan kode ${code}, menghentikan semua proses`);
    stopAll(code || 1);
  });
}

process.on('SIGINT', () => stopAll(0));
process.on('SIGTERM', () => stopAll(0));
