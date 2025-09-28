const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

let mainWindow;
const userDataPath = app.getPath('userData');
const filesListPath = path.join(userDataPath, 'files.json');

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.loadFile('index.html');
  
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
  }
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// Helper functions for persistent file storage
function saveFilesList(files) {
    try {
        console.log('Saving files list to:', filesListPath);
        console.log('Files to save:', files);
        fs.writeFileSync(filesListPath, JSON.stringify(files, null, 2));
        console.log('Files list saved successfully');
        return true;
    } catch (error) {
        console.error('Error saving files list:', error);
        return false;
    }
}

function loadFilesList() {
    try {
        console.log('Looking for files list at:', filesListPath);
        if (fs.existsSync(filesListPath)) {
            console.log('Files list exists, loading...');
            const data = fs.readFileSync(filesListPath, 'utf8');
            const files = JSON.parse(data);
            console.log('Loaded files:', files);
            return files;
        } else {
            console.log('Files list does not exist at:', filesListPath);
        }
    } catch (error) {
        console.error('Error loading files list:', error);
    }
    return [];
}

// IPC handlers for file operations
ipcMain.handle('load-files-on-startup', async () => {
  try {
    console.log('Loading files on startup...');
    const persistentFiles = loadFilesList();
    console.log('Loaded persistent files on startup:', persistentFiles.length);
    return persistentFiles;
  } catch (error) {
    console.error('Error loading files on startup:', error);
    return [];
  }
});

ipcMain.handle('scan-vulnerable-locations', async () => {
  // Load persistent files first
  const persistentFiles = loadFilesList();
  console.log('Loaded persistent files:', persistentFiles.length);
  
  const vulnerableLocations = [];
  const homeDir = process.env.HOME || process.env.USERPROFILE;
  
  // Default vulnerable locations
  const defaultLocations = [
    path.join(homeDir, '.ssh'),
    path.join(homeDir, '.aws'),
    path.join(homeDir, '.git-credentials'),
    path.join(homeDir, '.config', 'gh', 'hosts.yml')
  ];
  
  for (const location of defaultLocations) {
    if (fs.existsSync(location)) {
      vulnerableLocations.push({
        path: location,
        type: fs.statSync(location).isDirectory() ? 'directory' : 'file',
        encrypted: location.includes('_cyphered')
      });
    }
  }
  
  // If we have persistent files, use them as the primary source
  // Otherwise, use the scanned vulnerable locations
  if (persistentFiles.length > 0) {
    console.log('Returning persistent files');
    return persistentFiles;
  } else {
    console.log('Returning scanned vulnerable locations');
    return vulnerableLocations;
  }
});

ipcMain.handle('add-custom-path', async (event, customPath) => {
  if (fs.existsSync(customPath)) {
    const fileInfo = {
      path: customPath,
      type: fs.statSync(customPath).isDirectory() ? 'directory' : 'file',
      encrypted: customPath.includes('_cyphered')
    };
    
    // Add to persistent storage
    const persistentFiles = loadFilesList();
    if (!persistentFiles.some(file => file.path === customPath)) {
      persistentFiles.push(fileInfo);
      saveFilesList(persistentFiles);
    }
    
    return fileInfo;
  }
  throw new Error('Path does not exist');
});

ipcMain.handle('encrypt-file', async (event, filePath, key) => {
  try {
    console.log('Encrypting file:', filePath);
    if (!fs.existsSync(filePath)) {
      console.log('File does not exist at path:', filePath);
      throw new Error('File does not exist');
    }
    
    const stats = fs.statSync(filePath);
    let encryptedPath;
    
    if (stats.isDirectory()) {
      // For directories, create a zip first then encrypt
      const zipPath = filePath + '.zip';
      // In a real implementation, you would use a zip library here
      // For now, we'll simulate the process
      encryptedPath = filePath + '_cyphered.zip';
      
      // Simulate directory encryption by creating a marker file
      fs.writeFileSync(encryptedPath, 'Encrypted directory content');
    } else {
      // For files, encrypt directly
      const fileContent = fs.readFileSync(filePath, 'utf8');
      const algorithm = 'aes-256-cbc';
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipher(algorithm, key);
      let encryptedContent = cipher.update(fileContent, 'utf8', 'hex');
      encryptedContent += cipher.final('hex');
      encryptedPath = filePath.replace(/(\.[^/.]+)?$/, '_cyphered$&');
      fs.writeFileSync(encryptedPath, iv.toString('hex') + ':' + encryptedContent);
    }
    
    // Remove original file after encryption
    fs.unlinkSync(filePath);
    
    return {
      originalPath: filePath,
      encryptedPath: encryptedPath,
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
});

ipcMain.handle('decrypt-file', async (event, filePath, key) => {
  try {
    if (!fs.existsSync(filePath)) {
      throw new Error('File does not exist');
    }
    
    const stats = fs.statSync(filePath);
    let decryptedPath;
    
    if (stats.isDirectory() || filePath.endsWith('_cyphered.zip')) {
      // For encrypted directories
      decryptedPath = filePath.replace('_cyphered.zip', '');
      // In a real implementation, you would decrypt and unzip here
      // For now, we'll simulate the process
      fs.writeFileSync(decryptedPath, 'Decrypted directory content');
    } else {
      // For encrypted files
      const encryptedData = fs.readFileSync(filePath, 'utf8');
      const parts = encryptedData.split(':');
      if (parts.length !== 2) {
        throw new Error('Invalid encrypted file format');
      }
      
      const iv = Buffer.from(parts[0], 'hex');
      const encryptedContent = parts[1];
      const algorithm = 'aes-256-cbc';
      const decipher = crypto.createDecipher(algorithm, key);
      decipher.setAutoPadding(true);
      
      let decryptedContent = decipher.update(encryptedContent, 'hex', 'utf8');
      decryptedContent += decipher.final('utf8');
      
      if (!decryptedContent) {
        throw new Error('Invalid encryption key');
      }
      
      decryptedPath = filePath.replace('_cyphered', '');
      fs.writeFileSync(decryptedPath, decryptedContent);
    }
    
    // Remove encrypted file after decryption
    fs.unlinkSync(filePath);
    
    return {
      encryptedPath: filePath,
      decryptedPath: decryptedPath,
      success: true
    };
  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
});

ipcMain.handle('select-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile']
  });
  
  if (!result.canceled && result.filePaths.length > 0) {
    return result.filePaths[0];
  }
  return null;
});

ipcMain.handle('select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  
  if (!result.canceled && result.filePaths.length > 0) {
    return result.filePaths[0];
  }
  return null;
});

// IPC handler to update file list after encryption/decryption
ipcMain.handle('update-file-list', async (event, oldPath, newPath, isEncrypted) => {
  try {
    const persistentFiles = loadFilesList();
    
    // Normalize paths for comparison (handle both / and \ separators)
    const normalizePath = (path) => path.replace(/\\/g, '/');
    const normalizedOldPath = normalizePath(oldPath);
    
    // Remove the old file from the list (handle both separators)
    const updatedFiles = persistentFiles.filter(file => {
      const normalizedFilePath = normalizePath(file.path);
      return normalizedFilePath !== normalizedOldPath;
    });
    
    // Add the new file to the list
    const fileInfo = {
      path: newPath,
      type: fs.statSync(newPath).isDirectory() ? 'directory' : 'file',
      encrypted: isEncrypted
    };
    
    updatedFiles.push(fileInfo);
    saveFilesList(updatedFiles);
    
    return { success: true };
  } catch (error) {
    console.error('Error updating file list:', error);
    return { success: false, error: error.message };
  }
});