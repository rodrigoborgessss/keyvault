/*
 * build-argon2.js — gera public/vendor/argon2id.bundle.js
 *
 * Empacota a lib openpgpjs/argon2id num único ficheiro IIFE, com os dois
 * binários Wasm (SIMD e não-SIMD) embutidos em base64. Assim funciona offline
 * no Electron, sem fetch e sem passo de build no lado do utilizador.
 *
 * Só é preciso correr isto se quiseres atualizar a versão da lib:
 *   npm install argon2id esbuild
 *   node build-argon2.js
 */

const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

// Plugin: transforma cada `import x from '*.wasm'` num loader que instancia
// o módulo a partir dos bytes embutidos.
const wasmInline = {
  name: 'wasm-inline',
  setup(build) {
    build.onLoad({ filter: /\.wasm$/ }, async (args) => {
      const bytes = await fs.promises.readFile(args.path);
      const b64 = bytes.toString('base64');
      const contents = `
const _b64 = "${b64}";
const _bin = (typeof atob !== 'undefined') ? atob(_b64) : Buffer.from(_b64, 'base64').toString('binary');
const _bytes = new Uint8Array(_bin.length);
for (let i = 0; i < _bin.length; i++) _bytes[i] = _bin.charCodeAt(i);
export default (importObject) => WebAssembly.instantiate(_bytes, importObject);
`;
      return { contents, loader: 'js' };
    });
  }
};

const ENTRY = path.join(__dirname, '_argon2_entry.js');
fs.writeFileSync(
  ENTRY,
  `import loadWasm from 'argon2id';
const KVArgon2 = { loadWasm };
if (typeof window !== 'undefined') window.KVArgon2 = KVArgon2;
if (typeof globalThis !== 'undefined') globalThis.KVArgon2 = KVArgon2;
export default KVArgon2;
`,
  'utf8'
);

esbuild.build({
  entryPoints: [ENTRY],
  bundle: true,
  format: 'iife',
  target: ['es2020'],
  outfile: path.join(__dirname, 'public', 'vendor', 'argon2id.bundle.js'),
  plugins: [wasmInline],
  legalComments: 'inline'
}).then(() => {
  fs.unlinkSync(ENTRY);
  const out = path.join(__dirname, 'public', 'vendor', 'argon2id.bundle.js');
  const kb = (fs.statSync(out).size / 1024).toFixed(1);
  console.log(`OK: vendor/argon2id.bundle.js (${kb} KB)`);
}).catch((e) => {
  console.error('Falhou:', e);
  process.exit(1);
});
