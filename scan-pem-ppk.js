const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');

// Process 3: Scan for PEM and PPK files recursively in user directory
async function scanPemPpkFiles(homeDir) {
  const vulnerableFiles = [];
  
  try {
    // Recursively search for .pem and .ppk files
    await searchForFileTypes(homeDir, ['.pem', '.ppk'], vulnerableFiles);
    
    // Also scan for files containing SSH private keys regardless of filename
    await searchForSSHKeysInFiles(homeDir, vulnerableFiles);
  } catch (error) {
    console.error('Error scanning for PEM/PPK files:', error);
  }
  
  console.log('PEM/PPK scan found:', vulnerableFiles.length, 'files');
  return vulnerableFiles;
}

// Helper function to recursively search for file types
async function searchForFileTypes(dir, extensions, results) {
  try {
    const items = await fsPromises.readdir(dir);
    
    for (const item of items) {
      const fullPath = path.join(dir, item);
      
      try {
        const stats = await fsPromises.stat(fullPath);
        
        if (stats.isDirectory()) {
          // Skip some system directories to avoid permission issues
          const skipDirs = ['node_modules', '.git', '.cache', 'AppData', 'Library'];
          if (!skipDirs.some(skipDir => fullPath.includes(skipDir))) {
            await searchForFileTypes(fullPath, extensions, results);
          }
        } else if (stats.isFile()) {
          const ext = path.extname(item).toLowerCase();
          if (extensions.includes(ext)) {
            results.push({
              path: fullPath,
              type: 'file',
              encrypted: fullPath.includes('_cyphered')
            });
          }
        }
      } catch (error) {
        // Skip files/directories we can't access
        continue;
      }
    }
  } catch (error) {
    // Skip directories we can't access
    return;
  }
}

// Helper function to search for files containing SSH private keys
async function searchForSSHKeysInFiles(dir, results) {
  try {
    const items = await fsPromises.readdir(dir);
    
    for (const item of items) {
      const fullPath = path.join(dir, item);
      
      try {
        const stats = await fsPromises.stat(fullPath);
        
        if (stats.isDirectory()) {
          // Skip some system directories to avoid permission issues
          const skipDirs = ['node_modules', '.git', '.cache', 'AppData', 'Library', 'System32', 'Windows'];
          if (!skipDirs.some(skipDir => fullPath.includes(skipDir))) {
            await searchForSSHKeysInFiles(fullPath, results);
          }
        } else if (stats.isFile()) {
          // Skip files that are too large (> 1MB) or already in results
          if (stats.size > 1024 * 1024 || results.some(f => f.path === fullPath)) {
            continue;
          }
          
          // Check if file contains SSH private key patterns
          if (await containsSSHPrivateKey(fullPath)) {
            results.push({
              path: fullPath,
              type: 'file',
              encrypted: fullPath.includes('_cyphered'),
              detectedBy: 'ssh_key_content'
            });
          }
        }
      } catch (error) {
        // Skip files/directories we can't access
        continue;
      }
    }
  } catch (error) {
    // Skip directories we can't access
    return;
  }
}

// Helper function to check if file contains SSH private key patterns
async function containsSSHPrivateKey(filePath) {
  try {
    const content = await fsPromises.readFile(filePath, 'utf8');
    
    // Common SSH private key patterns
    const sshKeyPatterns = [
      /-----BEGIN RSA PRIVATE KEY-----/,
      /-----BEGIN DSA PRIVATE KEY-----/,
      /-----BEGIN EC PRIVATE KEY-----/,
      /-----BEGIN OPENSSH PRIVATE KEY-----/,
      /-----BEGIN PRIVATE KEY-----/,
      /-----BEGIN ENCRYPTED PRIVATE KEY-----/,
      /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
      /ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}/,
      /ssh-dss AAAA[0-9A-Za-z+/]+[=]{0,3}/,
      /ssh-ed25519 AAAA[0-9A-Za-z+/]+[=]{0,3}/,
      /ecdsa-sha2-nistp256 AAAA[0-9A-Za-z+/]+[=]{0,3}/
    ];
    
    return sshKeyPatterns.some(pattern => pattern.test(content));
  } catch (error) {
    // Skip files we can't read
    return false;
  }
}

module.exports = { scanPemPpkFiles };