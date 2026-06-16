/*
 * strength.js — estimativa de força por entropia
 *
 * Nota honesta: isto estima a entropia *teórica* assumindo escolha aleatória.
 * Para passwords escritas à mão é otimista (não deteta padrões tipo "Pedro2024!").
 * A verificação Pwned é o sinal mais fiável de que uma password é fraca na prática.
 */

function estimateStrength(password) {
  if (!password) {
    return { entropy: 0, label: 'vazia', score: 0, poolSize: 0 };
  }

  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;

  let entropy = password.length * Math.log2(pool || 1);

  // penalizações simples por padrões óbvios
  if (/(.)\1{2,}/.test(password)) entropy *= 0.85; // caracteres repetidos
  if (/^(?:0123|1234|2345|abcd|qwer|asdf)/i.test(password)) entropy *= 0.7; // sequências
  if (/^[a-zA-Z]+\d{1,4}!?$/.test(password)) entropy *= 0.8; // palavra+numeros classico

  entropy = Math.round(entropy);

  let label, score;
  if (entropy < 40) { label = 'fraca'; score = 1; }
  else if (entropy < 60) { label = 'razoável'; score = 2; }
  else if (entropy < 80) { label = 'forte'; score = 3; }
  else { label = 'excelente'; score = 4; }

  return { entropy, label, score, poolSize: pool };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { estimateStrength };
}
