/*
 * crypto.js — cifra do cofre, do lado do cliente (zero-knowledge)
 *
 * Derivação de chave: Argon2id (RFC 9106, lib openpgpjs) -> chave AES-256-GCM.
 * O Argon2id é usado como KDF (derivar a CHAVE de cifra), não como verificador
 * de password: não guardamos nenhum hash da master password. O que fica guardado
 * é salt + parâmetros + ciphertext. A chave derivada vive só em memória.
 *
 * Cofres antigos (v1, PBKDF2) continuam a abrir e são migrados para Argon2id
 * na próxima gravação.
 */

const KV_ARGON2_DEFAULTS = {
  memorySize: 65536, // KiB = 64 MiB
  passes: 3,
  parallelism: 1,
  tagLength: 32      // 32 bytes -> AES-256
};
const KV_PBKDF2_ITERATIONS = 600000; // legado

const _enc = new TextEncoder();
const _dec = new TextDecoder();

function _buf2b64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function _b642bytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Carrega o Wasm uma vez e reutiliza a função.
let _argon2Fn = null;
async function _getArgon2() {
  if (_argon2Fn) return _argon2Fn;
  const lib = (typeof globalThis !== 'undefined' && globalThis.KVArgon2)
    ? globalThis.KVArgon2 : (typeof KVArgon2 !== 'undefined' ? KVArgon2 : null);
  if (!lib || !lib.loadWasm) {
    throw new Error('Biblioteca Argon2 não carregada (vendor/argon2id.bundle.js)');
  }
  _argon2Fn = await lib.loadWasm();
  return _argon2Fn;
}

async function _deriveKeyArgon2(masterPassword, salt, p) {
  const argon2id = await _getArgon2();
  const keyBytes = argon2id({
    password: _enc.encode(masterPassword),
    salt,
    parallelism: p.parallelism,
    passes: p.passes,
    memorySize: p.memorySize,
    tagLength: p.tagLength
  });
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function _deriveKeyPBKDF2(masterPassword, salt, iterations) {
  const baseKey = await crypto.subtle.importKey(
    'raw', _enc.encode(masterPassword), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function isLegacyKdf(blob) {
  return !blob || blob.kdf !== 'argon2id';
}

// Cifra sempre com Argon2id (v2).
async function encryptVault(plainObject, masterPassword) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const p = KV_ARGON2_DEFAULTS;
  const key = await _deriveKeyArgon2(masterPassword, salt, p);
  const data = _enc.encode(JSON.stringify(plainObject));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return {
    v: 2,
    kdf: 'argon2id',
    argon2: {
      memorySize: p.memorySize,
      passes: p.passes,
      parallelism: p.parallelism,
      tagLength: p.tagLength
    },
    salt: _buf2b64(salt),
    iv: _buf2b64(iv),
    ciphertext: _buf2b64(ciphertext)
  };
}

// Decifra v2 (Argon2id) ou v1 (PBKDF2, legado).
async function decryptVault(blob, masterPassword) {
  const salt = _b642bytes(blob.salt);
  const iv = _b642bytes(blob.iv);
  let key;
  if (blob.kdf === 'argon2id') {
    key = await _deriveKeyArgon2(masterPassword, salt, blob.argon2 || KV_ARGON2_DEFAULTS);
  } else {
    key = await _deriveKeyPBKDF2(masterPassword, salt, blob.iterations || KV_PBKDF2_ITERATIONS);
  }
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, _b642bytes(blob.ciphertext));
  return JSON.parse(_dec.decode(plaintext));
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    encryptVault, decryptVault, isLegacyKdf,
    _deriveKeyPBKDF2, _buf2b64, KV_ARGON2_DEFAULTS, KV_PBKDF2_ITERATIONS
  };
}
