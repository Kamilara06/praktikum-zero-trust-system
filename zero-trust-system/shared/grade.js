'use strict';

/** Konversi nilai angka (0 sampai 100) ke nilai huruf. Dipakai seed dan Service Nilai. */
function toLetter(score) {
  if (score >= 85) return 'A';
  if (score >= 80) return 'A-';
  if (score >= 75) return 'B+';
  if (score >= 70) return 'B';
  if (score >= 65) return 'C+';
  if (score >= 60) return 'C';
  if (score >= 50) return 'D';
  return 'E';
}

module.exports = { toLetter };
