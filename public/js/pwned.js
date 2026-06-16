/*
 * pwned.js — verificação contra a base "Pwned Passwords" do HIBP
 *
 * Usa k-anonymity: só os primeiros 5 caracteres do hash SHA-1 saem da máquina.
 * A password completa e o hash completo NUNCA são enviados para lado nenhum.
 * A chamada vai direta do browser para a API (tem CORS), não passa pelo servidor.
 */

async function sha1Hex(text) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

async function checkPwned(password) {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { 'Add-Padding': 'true' } // privacidade extra: respostas com tamanho uniforme
  });
  if (!res.ok) throw new Error(`API Pwned Passwords respondeu ${res.status}`);

  const text = await res.text();
  let count = 0;
  for (const line of text.split('\n')) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const suf = line.slice(0, idx).trim().toUpperCase();
    const cnt = parseInt(line.slice(idx + 1).trim(), 10);
    if (suf === suffix) {
      count = cnt;
      break;
    }
  }

  return { hash, prefix, suffix, count, pwned: count > 0 };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { sha1Hex, checkPwned };
}
