/*
 * server.js — servidor local do KeyVault (sem dependências, só Node)
 *
 * Responsabilidades:
 *   - servir os ficheiros estáticos de /public
 *   - guardar/devolver o BLOB CIFRADO do cofre (data/vault.json)
 *
 * O servidor é "zero-knowledge": só vê texto cifrado. Nunca recebe a master
 * password nem dados em claro. Liga-se apenas a 127.0.0.1 (não exposto na rede).
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const HOST = '127.0.0.1';
const PORT = process.env.PORT || 7700;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const VAULT_FILE = path.join(DATA_DIR, 'vault.json');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 5 * 1024 * 1024) {
        reject(new Error('payload demasiado grande'));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function serveStatic(req, res) {
  let rel = decodeURIComponent(req.url.split('?')[0]);
  if (rel === '/') rel = '/index.html';

  // proteção contra path traversal
  const target = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!target.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(target, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Não encontrado');
      return;
    }
    const ext = path.extname(target).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store'
    });
    res.end(content);
  });
}

const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];

  // ---- API do cofre ----
  if (url === '/api/vault') {
    try {
      if (req.method === 'GET') {
        if (!fs.existsSync(VAULT_FILE)) {
          return sendJSON(res, 200, { exists: false, blob: null });
        }
        const blob = JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8'));
        return sendJSON(res, 200, { exists: true, blob });
      }

      if (req.method === 'PUT') {
        const raw = await readBody(req);
        const blob = JSON.parse(raw);
        // validação mínima da forma do blob cifrado
        if (!blob || !blob.ciphertext || !blob.salt || !blob.iv) {
          return sendJSON(res, 400, { error: 'blob inválido' });
        }
        fs.writeFileSync(VAULT_FILE, JSON.stringify(blob), 'utf8');
        return sendJSON(res, 200, { ok: true });
      }

      if (req.method === 'DELETE') {
        if (fs.existsSync(VAULT_FILE)) fs.unlinkSync(VAULT_FILE);
        return sendJSON(res, 200, { ok: true });
      }

      return sendJSON(res, 405, { error: 'método não permitido' });
    } catch (e) {
      return sendJSON(res, 500, { error: e.message });
    }
  }

  // ---- ficheiros estáticos ----
  if (req.method === 'GET') return serveStatic(req, res);

  res.writeHead(405);
  res.end('Method Not Allowed');
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  KeyVault a correr');
  console.log(`  Abre no browser:  http://${HOST}:${PORT}`);
  console.log('  Para parar: Ctrl+C');
  console.log('');
});
