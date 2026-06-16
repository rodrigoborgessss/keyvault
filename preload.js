/*
 * preload.js — ponte segura entre a frontend e o processo principal.
 *
 * Expõe apenas o necessário para guardar/ler o blob cifrado. A frontend nunca
 * tem acesso direto ao Node nem ao sistema de ficheiros.
 */

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vaultAPI', {
  load: () => ipcRenderer.invoke('vault:load'),
  save: (blob) => ipcRenderer.invoke('vault:save', blob),
  remove: () => ipcRenderer.invoke('vault:remove')
});
