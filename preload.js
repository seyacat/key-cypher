const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  loadFilesOnStartup: () => ipcRenderer.invoke('load-files-on-startup'),
  scanVulnerableLocations: () => ipcRenderer.invoke('scan-vulnerable-locations'),
  addCustomPath: (customPath) => ipcRenderer.invoke('add-custom-path', customPath),
  encryptFile: (filePath, key) => ipcRenderer.invoke('encrypt-file', filePath, key),
  decryptFile: (filePath, key) => ipcRenderer.invoke('decrypt-file', filePath, key),
  selectFile: () => ipcRenderer.invoke('select-file'),
  selectDirectory: () => ipcRenderer.invoke('select-directory'),
  updateFileList: (oldPath, newPath, isEncrypted) => ipcRenderer.invoke('update-file-list', oldPath, newPath, isEncrypted)
});