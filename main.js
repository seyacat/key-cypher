const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

let mainWindow;

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

// IPC handlers for file operations
ipcMain.handle('scan-vulnerable-locations', async () => {
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
  
  return vulnerableLocations;
});

ipcMain.handle('add-custom-path', async (event, customPath) => {
  if (fs.existsSync(customPath)) {
    return {
      path: customPath,
      type: fs.statSync(customPath).isDirectory() ? 'directory' : 'file',
      encrypted: customPath.includes('_cyphered')
    };
  }
  throw new Error('Path does not exist');
});

ipcMain.handle('encrypt-file', async (event, filePath, key) => {
  try {
    if (!fs.existsSync(filePath)) {
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

ipcMain.handle('select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  
  if (!result.canceled && result.filePaths.length > 0) {
    return result.filePaths[0];
  }
  return null;
});