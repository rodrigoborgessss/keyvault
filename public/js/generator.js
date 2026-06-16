/*
 * generator.js — gerador de passwords com aleatoriedade criptográfica
 *
 * Usa crypto.getRandomValues com rejection sampling para evitar viés de módulo.
 */

const KV_SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?'
};

const KV_AMBIGUOUS = new Set(['I', 'l', '1', 'O', '0', 'o', 'B', '8', 'S', '5']);

// Inteiro uniforme em [0, max) sem viés de módulo.
function _randInt(max) {
  if (max <= 0) return 0;
  const limit = Math.floor(0xffffffff / max) * max;
  const arr = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(arr);
    x = arr[0];
  } while (x >= limit);
  return x % max;
}

function _pick(str) {
  return str[_randInt(str.length)];
}

function _clean(str, excludeAmbiguous) {
  if (!excludeAmbiguous) return str;
  return [...str].filter((c) => !KV_AMBIGUOUS.has(c)).join('');
}

function generatePassword(opts = {}) {
  const {
    length = 18,
    lower = true,
    upper = true,
    digits = true,
    symbols = true,
    excludeAmbiguous = false
  } = opts;

  const active = [];
  if (lower) active.push(_clean(KV_SETS.lower, excludeAmbiguous));
  if (upper) active.push(_clean(KV_SETS.upper, excludeAmbiguous));
  if (digits) active.push(_clean(KV_SETS.digits, excludeAmbiguous));
  if (symbols) active.push(_clean(KV_SETS.symbols, excludeAmbiguous));

  const sets = active.filter((s) => s.length > 0);
  if (sets.length === 0) return '';

  const pool = sets.join('');
  const len = Math.max(length, sets.length);
  const chars = [];

  // garante pelo menos um caractere de cada conjunto ativo
  for (const s of sets) chars.push(_pick(s));
  while (chars.length < len) chars.push(_pick(pool));

  // Fisher-Yates para baralhar as posições garantidas
  for (let i = chars.length - 1; i > 0; i--) {
    const j = _randInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  return chars.join('');
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { generatePassword, KV_SETS };
}
