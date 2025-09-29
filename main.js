const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const fsPromises = require('fs').promises;
const crypto = require('crypto');
const archiver = require('archiver');
const unzipper = require('unzipper');

// Import scan modules
const { scanVulnerableDirectories } = require('./scan-directories');
const { scanSingleFiles } = require('./scan-single-files');
const { scanPemPpkFiles } = require('./scan-pem-ppk');
const { scanSSHKeys } = require('./scan-ssh-keys');
const { scanCypheredFiles } = require('./scan-cypher-ed-files');
const { scanEnvFiles } = require('./scan-env-files');

// Helper function to delay execution
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Helper function to retry an operation with delay
async function retryOperation(operation, maxRetries = 3, delayMs = 100) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      if (attempt === maxRetries) {
        throw error;
      }
      console.log(`Retry attempt ${attempt} failed, waiting ${delayMs}ms before next attempt`);
      await delay(delayMs);
    }
  }
}

// Helper function to delete files/directories
async function deleteFileOrDirectory(filePath) {
  try {
    const stats = await fsPromises.stat(filePath);
    
    if (stats.isDirectory()) {
      // For directories, delete recursively
      await deleteDirectoryRecursive(filePath);
    } else {
      // For files, use fs.unlink
      await fsPromises.unlink(filePath);
    }
    return true;
  } catch (error) {
    console.error('Error deleting file/directory:', error);
    throw error;
  }
}

// Helper function to delete directories recursively
async function deleteDirectoryRecursive(dirPath) {
  try {
    const items = await fsPromises.readdir(dirPath);
    
    for (const item of items) {
      const fullPath = path.join(dirPath, item);
      const stats = await fsPromises.stat(fullPath);
      
      if (stats.isDirectory()) {
        await deleteDirectoryRecursive(fullPath);
      } else {
        await fsPromises.unlink(fullPath);
      }
    }
    
    // After deleting all contents, delete the directory itself
    await fsPromises.rmdir(dirPath);
  } catch (error) {
    console.error('Error deleting directory recursively:', error);
    throw error;
  }
}

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

  // Remove the menu bar
  mainWindow.setMenuBarVisibility(false);

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
function checkFilePermissions(filePath) {
    try {
        const stats = fs.statSync(filePath);
        const permissions = {
            readable: true, // We can read it
            writable: false,
            deletable: true // Assume deletable by default
        };
        
        // Check if we can write to the file
        try {
            fs.accessSync(filePath, fs.constants.W_OK);
            permissions.writable = true;
        } catch (e) {
            permissions.writable = false;
        }
        
        return permissions;
    } catch (error) {
        return {
            readable: false,
            writable: false,
            deletable: false,
            error: error.message
        };
    }
}

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
  const homeDir = process.env.HOME || process.env.USERPROFILE;
  const allVulnerableFiles = [];
  
  // Run all scan processes asynchronously using separate modules
  const scanProcesses = [
    scanVulnerableDirectories(homeDir),
    scanSingleFiles(homeDir),
    scanPemPpkFiles(homeDir),
    scanSSHKeys(homeDir),
    scanCypheredFiles(homeDir),
    scanEnvFiles(homeDir)
  ];
  
  // Wait for all processes to complete
  const results = await Promise.allSettled(scanProcesses);
  
  // Collect all files from successful processes
  results.forEach(result => {
    if (result.status === 'fulfilled' && result.value.length > 0) {
      allVulnerableFiles.push(...result.value);
    }
  });
  
  // Add scanned files to persistent storage
  if (allVulnerableFiles.length > 0) {
    const persistentFiles = loadFilesList();
    const existingPaths = new Set(persistentFiles.map(file => file.path.replace(/\\/g, '/')));
    
    allVulnerableFiles.forEach(file => {
      const normalizedPath = file.path.replace(/\\/g, '/');
      if (!existingPaths.has(normalizedPath)) {
        persistentFiles.push(file);
        existingPaths.add(normalizedPath);
      }
    });
    
    saveFilesList(persistentFiles);
  }
  
  console.log('Total scanned vulnerable files:', allVulnerableFiles.length);
  return allVulnerableFiles;
});

// Background scan functionality
ipcMain.handle('start-background-scan', async (event) => {
  const homeDir = process.env.HOME || process.env.USERPROFILE;
  
  // Start background scan without blocking
  backgroundScan(homeDir, event.sender);
  
  return { success: true, message: 'Background scan started' };
});

// Background scan function that sends incremental updates
async function backgroundScan(homeDir, sender) {
  console.log('Starting background scan...');
  
  // Run all scan processes in parallel but process results as they complete
  try {
    const scanProcesses = [
      { name: 'Directory scan', func: scanVulnerableDirectories(homeDir) },
      { name: 'Single files scan', func: scanSingleFiles(homeDir) },
      { name: 'PEM/PPK scan', func: scanPemPpkFiles(homeDir) },
      { name: 'SSH keys scan', func: scanSSHKeys(homeDir) },
      { name: 'Cyphered files scan', func: scanCypheredFiles(homeDir) },
      { name: 'Env files scan', func: scanEnvFiles(homeDir) }
    ];
    
    let totalFilesFound = 0;
    
    // Process each scan as it completes
    for (const scan of scanProcesses) {
      try {
        const files = await scan.func;
        
        if (files.length > 0) {
          totalFilesFound += files.length;
          
          // Add to persistent storage and send update immediately
          addFilesToPersistentStorage(files);
          sender.send('background-scan-update', files);
          
          console.log(`${scan.name} completed:`, files.length, 'files');
        }
      } catch (error) {
        console.error(`${scan.name} failed:`, error);
      }
    }
    
    // Send completion signal
    sender.send('background-scan-complete', {
      success: true,
      message: 'Background scan completed',
      totalFiles: totalFilesFound
    });
    
    console.log('Background scan completed successfully. Total files found:', totalFilesFound);
    
  } catch (error) {
    console.error('Background scan error:', error);
    sender.send('background-scan-complete', {
      success: false,
      error: error.message
    });
  }
}

// Helper function to add files to persistent storage
async function addFilesToPersistentStorage(newFiles) {
  if (newFiles.length > 0) {
    const persistentFiles = loadFilesList();
    const existingPaths = new Set(persistentFiles.map(file => file.path.replace(/\\/g, '/')));
    
    let addedCount = 0;
    newFiles.forEach(file => {
      const normalizedPath = file.path.replace(/\\/g, '/');
      if (!existingPaths.has(normalizedPath)) {
        persistentFiles.push(file);
        existingPaths.add(normalizedPath);
        addedCount++;
      }
    });
    
    if (addedCount > 0) {
      saveFilesList(persistentFiles);
      console.log('Added', addedCount, 'files to persistent storage');
    }
  }
}
  
  // Backup functionality
  ipcMain.handle('create-backup', async (event, encryptionKey = null) => {
    try {
      const persistentFiles = loadFilesList();
      
      if (persistentFiles.length === 0) {
        return { success: false, error: 'No files to backup' };
      }
      
      // Create timestamp for backup filename
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
      const backupFilename = `cypher_backup_${timestamp}.zip`;
      const homeDir = process.env.HOME || process.env.USERPROFILE;
      const backupPath = path.join(homeDir, backupFilename);
      
      // Ensure home directory exists
      await fsPromises.mkdir(homeDir, { recursive: true });
      
      console.log('Creating backup at:', backupPath);
      
      // Create ZIP archive directly to backup path
      await new Promise((resolve, reject) => {
        const output = fs.createWriteStream(backupPath);
        const archive = archiver('zip', {
          zlib: { level: 9 } // Maximum compression
        });
        
        output.on('close', () => {
          console.log('Backup created successfully:', archive.pointer() + ' total bytes');
          resolve();
        });
        
        archive.on('error', reject);
        archive.on('warning', (err) => {
          if (err.code === 'ENOENT') {
            console.warn('Backup warning:', err);
          } else {
            reject(err);
          }
        });
        
        archive.pipe(output);
        
        // Add each file to the archive with relative path structure
        persistentFiles.forEach(file => {
          if (fs.existsSync(file.path) && fs.statSync(file.path).isFile()) {
            try {
              // Create relative path structure from drive root
              const relativePath = path.relative(path.parse(file.path).root, file.path);
              archive.file(file.path, { name: relativePath });
              console.log('Added to backup:', relativePath);
            } catch (error) {
              console.warn('Skipping file for backup:', file.path, error.message);
            }
          }
        });

        // Add the files.json metadata file to the backup
        if (fs.existsSync(filesListPath)) {
          archive.file(filesListPath, { name: 'files.json' });
          console.log('Added metadata file to backup: files.json');
        }
        
        archive.finalize();
      });
      
      console.log('Backup created successfully');
      
      let finalBackupPath = backupPath;
      let isEncrypted = false;
      
      // If encryption key is provided, encrypt the backup immediately
      if (encryptionKey) {
        console.log('Encrypting backup with provided key...');
        const algorithm = 'aes-256-cbc';
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher(algorithm, encryptionKey);
        
        const backupContent = await fsPromises.readFile(backupPath);
        let encryptedContent = Buffer.concat([
          cipher.update(backupContent),
          cipher.final()
        ]);
        
        finalBackupPath = backupPath.replace('.zip', '_cyphered.zip');
        await fsPromises.writeFile(finalBackupPath, Buffer.concat([
          iv,
          encryptedContent
        ]));
        
        // Remove the original unencrypted backup
        await fsPromises.unlink(backupPath);
        
        isEncrypted = true;
        console.log('Backup encrypted successfully:', finalBackupPath);
      }
      
      // Add the backup file to the files list for encryption consideration
      const backupFileInfo = {
        path: finalBackupPath,
        type: 'file',
        encrypted: isEncrypted
      };
      
      // Check if backup file already exists in the list
      const existingPaths = new Set(persistentFiles.map(file => file.path.replace(/\\/g, '/')));
      const normalizedBackupPath = finalBackupPath.replace(/\\/g, '/');
      
      if (!existingPaths.has(normalizedBackupPath)) {
        persistentFiles.push(backupFileInfo);
        saveFilesList(persistentFiles);
        console.log('Backup file added to files list:', finalBackupPath, 'Encrypted:', isEncrypted);
      }
      
      return {
        success: true,
        backupPath: finalBackupPath,
        message: `Backup created${isEncrypted ? ' and encrypted' : ''}: ${path.basename(finalBackupPath)}`,
        encrypted: isEncrypted
      };
      
    } catch (error) {
      console.error('Backup error:', error);
      return {
        success: false,
        error: error.message
      };
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
  let encryptedPath = null;
  try {
    console.log('Encrypting file:', filePath);
    
    // Check if file exists using async method
    try {
      await fsPromises.access(filePath);
    } catch (error) {
      console.log('File does not exist at path:', filePath);
      throw new Error('File does not exist');
    }
    
    // Check basic permissions before proceeding
    const permissions = checkFilePermissions(filePath);
    console.log('File permissions:', permissions);
    
    const stats = await fsPromises.stat(filePath);
    
    if (stats.isDirectory()) {
      // For directories: compress to ZIP first, then encrypt the ZIP
      const zipPath = filePath + '.zip';
      encryptedPath = filePath + '_cypheredd.zip';
      
      // Create ZIP archive
      await new Promise((resolve, reject) => {
        const output = fs.createWriteStream(zipPath);
        const archive = archiver('zip', {
          zlib: { level: 9 } // Maximum compression
        });
        
        output.on('close', resolve);
        archive.on('error', reject);
        
        archive.pipe(output);
        archive.directory(filePath, false);
        archive.finalize();
      });
      
      // Encrypt the ZIP file
      const zipContent = await fsPromises.readFile(zipPath);
      const algorithm = 'aes-256-cbc';
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipher(algorithm, key);
      let encryptedContent = cipher.update(zipContent, 'binary', 'hex');
      encryptedContent += cipher.final('hex');
      await fsPromises.writeFile(encryptedPath, iv.toString('hex') + ':' + encryptedContent);
      
      // Remove temporary ZIP file
      await fsPromises.unlink(zipPath);
    } else {
      // For files, encrypt directly
      const fileContent = await fsPromises.readFile(filePath, 'utf8');
      const algorithm = 'aes-256-cbc';
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipher(algorithm, key);
      let encryptedContent = cipher.update(fileContent, 'utf8', 'hex');
      encryptedContent += cipher.final('hex');
      encryptedPath = filePath.replace(/(\.[^/.]+)?$/, '_cyphered$&');
      await fsPromises.writeFile(encryptedPath, iv.toString('hex') + ':' + encryptedContent);
    }
    
    // Add delay before attempting to delete the original file
    console.log('Waiting 500ms before deleting original file...');
    await delay(500);
    
    // Remove original file after encryption
    await deleteFileOrDirectory(filePath);
    
    console.log('Original file successfully deleted');
    
    return {
      originalPath: filePath,
      encryptedPath: encryptedPath,
      success: true
    };
  } catch (error) {
    // Rollback: if encrypted file was created but original couldn't be deleted, remove the encrypted file
    if (encryptedPath) {
      try {
        await fsPromises.access(encryptedPath);
        await fsPromises.unlink(encryptedPath);
        console.log('Rollback: removed encrypted file due to error:', encryptedPath);
      } catch (rollbackError) {
        console.error('Rollback failed for encrypted file:', rollbackError);
      }
    }
    
    return {
      success: false,
      error: error.message
    };
  }
});

ipcMain.handle('decrypt-file', async (event, filePath, key) => {
  let decryptedPath = null;
  try {
    // Check if file exists using async method
    try {
      await fsPromises.access(filePath);
    } catch (error) {
      throw new Error('File does not exist');
    }
    
    const stats = await fsPromises.stat(filePath);
    
    if (filePath.endsWith('_cypheredd.zip')) {
      // For encrypted directories: decrypt the ZIP, then extract
      decryptedPath = filePath.replace('_cypheredd.zip', '');
      
      // Decrypt the ZIP file
      const encryptedData = await fsPromises.readFile(filePath);
      const parts = encryptedData.toString().split(':');
      if (parts.length !== 2) {
        throw new Error('Invalid encrypted directory format');
      }
      
      const iv = Buffer.from(parts[0], 'hex');
      const encryptedContent = parts[1];
      const algorithm = 'aes-256-cbc';
      const decipher = crypto.createDecipher(algorithm, key);
      decipher.setAutoPadding(true);
      
      let decryptedZipContent = decipher.update(encryptedContent, 'hex', 'binary');
      decryptedZipContent += decipher.final('binary');
      
      // Write decrypted ZIP to temporary file
      const tempZipPath = filePath.replace('_cypheredd.zip', '_temp.zip');
      await fsPromises.writeFile(tempZipPath, decryptedZipContent, 'binary');
      
      // Extract ZIP to destination
      await new Promise((resolve, reject) => {
        fs.createReadStream(tempZipPath)
          .pipe(unzipper.Extract({ path: decryptedPath }))
          .on('close', resolve)
          .on('error', reject);
      });
      
      // Remove temporary ZIP file
      await fsPromises.unlink(tempZipPath);
    } else {
      // For encrypted files - handle both text and binary formats
      const encryptedData = await fsPromises.readFile(filePath);
      
      // Check if it's a binary encrypted file (backup) or text encrypted file
      if (filePath.endsWith('_cyphered.zip')) {
        // Binary file encryption (backup files) - format: IV (16 bytes) + encrypted data
        if (encryptedData.length < 16) {
          throw new Error('Invalid encrypted file format');
        }
        
        const iv = encryptedData.slice(0, 16);
        const encryptedContent = encryptedData.slice(16);
        const algorithm = 'aes-256-cbc';
        const decipher = crypto.createDecipher(algorithm, key);
        decipher.setAutoPadding(true);
        
        let decryptedContent = Buffer.concat([
          decipher.update(encryptedContent),
          decipher.final()
        ]);
        
        decryptedPath = filePath.replace('_cyphered.zip', '.zip');
        await fsPromises.writeFile(decryptedPath, decryptedContent);
      } else {
        // Text file encryption (original logic) - format: hex(iv):hex(encrypted)
        const encryptedText = encryptedData.toString('utf8');
        const parts = encryptedText.split(':');
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
        await fsPromises.writeFile(decryptedPath, decryptedContent);
      }
    }
    
    // Add delay before attempting to delete the encrypted file
    console.log('Waiting 500ms before deleting encrypted file...');
    await delay(500);
    
    // Remove encrypted file after decryption
    await deleteFileOrDirectory(filePath);
    
    console.log('Encrypted file successfully deleted');
    
    return {
      encryptedPath: filePath,
      decryptedPath: decryptedPath,
      success: true
    };
  } catch (error) {
    // Rollback: if decrypted file was created but encrypted couldn't be deleted, remove the decrypted file
    if (decryptedPath) {
      try {
        await fsPromises.access(decryptedPath);
        await fsPromises.unlink(decryptedPath);
        console.log('Rollback: removed decrypted file due to error:', decryptedPath);
      } catch (rollbackError) {
        console.error('Rollback failed for decrypted file:', rollbackError);
      }
    }
    
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
    
    // Add the new file to the list - use suffix-based detection for encrypted files
    const fileType = newPath.endsWith('_cypheredd.zip') ? 'directory' :
                    newPath.includes('_cyphered') ? 'file' :
                    fs.statSync(newPath).isDirectory() ? 'directory' : 'file';
    
    const fileInfo = {
      path: newPath,
      type: fileType,
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

ipcMain.handle('remove-file-from-list', async (event, filePath) => {
  try {
    const persistentFiles = loadFilesList();
    
    // Normalize paths for comparison (handle both / and \ separators)
    const normalizePath = (path) => path.replace(/\\/g, '/');
    const normalizedFilePath = normalizePath(filePath);
    
    // Remove the file from the list (handle both separators)
    const updatedFiles = persistentFiles.filter(file => {
      const normalizedCurrentPath = normalizePath(file.path);
      return normalizedCurrentPath !== normalizedFilePath;
    });
    
    saveFilesList(updatedFiles);
    
    return { success: true };
  } catch (error) {
    console.error('Error removing file from list:', error);
    return { success: false, error: error.message };
  }
});

// IPC handler to check file status and detect conflicts
ipcMain.handle('check-file-status', async (event, filePath) => {
  try {
    const exists = fs.existsSync(filePath);
    let status = 'OK';
    let hasConflict = false;
    
    if (!exists) {
      status = 'MISSING';
    } else {
      // Check for file pair conflicts
      if (filePath.includes('_cyphered')) {
        // This is an encrypted file, check if original exists
        const originalPath = filePath.replace('_cyphered', '');
        if (fs.existsSync(originalPath)) {
          status = 'CONFLICT';
          hasConflict = true;
        }
      } else {
        // This is an original file, check if encrypted version exists
        const encryptedPath = filePath.replace(/(\.[^/.]+)?$/, '_cyphered$&');
        if (fs.existsSync(encryptedPath)) {
          status = 'CONFLICT';
          hasConflict = true;
        }
      }
    }
    
    return {
      exists: exists,
      status: status,
      hasConflict: hasConflict
    };
  } catch (error) {
    console.error('Error checking file status:', error);
    return {
      exists: false,
      status: 'ERROR',
      hasConflict: false,
      error: error.message
    };
  }
});

// IPC handler to open file in explorer
ipcMain.handle('open-file-in-explorer', async (event, filePath) => {
  try {
    // Check if file exists
    if (fs.existsSync(filePath)) {
      // Open the file directly - this will select it in Windows Explorer
      shell.showItemInFolder(filePath);
    } else {
      // If file doesn't exist, try to open the parent directory
      const directory = path.dirname(filePath);
      if (fs.existsSync(directory)) {
        shell.openPath(directory);
      } else {
        throw new Error('Directory does not exist');
      }
    }
    return { success: true };
  } catch (error) {
    console.error('Error opening file in explorer:', error);
    return { success: false, error: error.message };
  }
});