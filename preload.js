const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  loadFilesOnStartup: () => ipcRenderer.invoke('load-files-on-startup'),
  scanVulnerableLocations: () => ipcRenderer.invoke('scan-vulnerable-locations'),
  startBackgroundScan: () => ipcRenderer.invoke('start-background-scan'),
  addCustomPath: (customPath) => ipcRenderer.invoke('add-custom-path', customPath),
  encryptFile: (filePath, key) => ipcRenderer.invoke('encrypt-file', filePath, key),
  decryptFile: (filePath, key) => ipcRenderer.invoke('decrypt-file', filePath, key),
  selectFile: () => ipcRenderer.invoke('select-file'),
  selectDirectory: () => ipcRenderer.invoke('select-directory'),
  updateFileList: (oldPath, newPath, isEncrypted) => ipcRenderer.invoke('update-file-list', oldPath, newPath, isEncrypted),
  removeFileFromList: (filePath) => ipcRenderer.invoke('remove-file-from-list', filePath),
  checkFileStatus: (filePath) => ipcRenderer.invoke('check-file-status', filePath),
  openFileInExplorer: (filePath) => ipcRenderer.invoke('open-file-in-explorer', filePath),
  onBackgroundScanUpdate: (callback) => ipcRenderer.on('background-scan-update', callback),
  onBackgroundScanComplete: (callback) => ipcRenderer.on('background-scan-complete', callback)
});