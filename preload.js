const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  scanVulnerableLocations: () => ipcRenderer.invoke('scan-vulnerable-locations'),
  addCustomPath: (customPath) => ipcRenderer.invoke('add-custom-path', customPath),
  encryptFile: (filePath, key) => ipcRenderer.invoke('encrypt-file', filePath, key),
  decryptFile: (filePath, key) => ipcRenderer.invoke('decrypt-file', filePath, key),
  selectDirectory: () => ipcRenderer.invoke('select-directory')
});