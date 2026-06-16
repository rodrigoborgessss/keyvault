/*
 * storage.js — abstrai onde o cofre cifrado é guardado.
 *
 *  - No Electron: via IPC para o processo principal (ficheiro em userData).
 *  - No browser (servidor local): via HTTP para /api/vault.
 *
 * A mesma frontend funciona nos dois modos sem alterações.
 */

const Storage = (() => {
  const electron = (typeof window !== 'undefined' && window.vaultAPI) ? window.vaultAPI : null;

  return {
    mode: electron ? 'electron' : 'web',

    async load() {
      if (electron) return electron.load();
      const res = await fetch('/api/vault');
      return res.json();
    },

    async save(blob) {
      if (electron) { await electron.save(blob); return; }
      const res = await fetch('/api/vault', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(blob)
      });
      if (!res.ok) throw new Error('Falha ao guardar');
    },

    async remove() {
      if (electron) { await electron.remove(); return; }
      await fetch('/api/vault', { method: 'DELETE' });
    }
  };
})();
