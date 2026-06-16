/*
 * main.js — processo principal do Electron
 *
 * Cria a janela e trata do armazenamento do cofre cifrado via IPC.
 * O cofre fica em <userData>/vault.json (cifrado). Não abre porta de rede.
 */

const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');

function vaultFile() {
  return path.join(app.getPath('userData'), 'vault.json');
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1120,
    height: 780,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0b0e16',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  win.removeMenu();
  win.loadFile(path.join(__dirname, 'public', 'index.html'));

  // links externos abrem no browser do sistema, não dentro da app
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });
}

// ---- IPC: armazenamento do cofre ----
ipcMain.handle('vault:load', () => {
  const f = vaultFile();
  if (!fs.existsSync(f)) return { exists: false, blob: null };
  try {
    return { exists: true, blob: JSON.parse(fs.readFileSync(f, 'utf8')) };
  } catch {
    return { exists: false, blob: null };
  }
});

ipcMain.handle('vault:save', (_e, blob) => {
  if (!blob || !blob.ciphertext || !blob.salt || !blob.iv) {
    throw new Error('blob inválido');
  }
  fs.writeFileSync(vaultFile(), JSON.stringify(blob), 'utf8');
  return { ok: true };
});

ipcMain.handle('vault:remove', () => {
  const f = vaultFile();
  if (fs.existsSync(f)) fs.unlinkSync(f);
  return { ok: true };
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
