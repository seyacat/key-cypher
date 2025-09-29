const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');

// Process: Scan for SSH private keys by content in files without extensions
async function scanSSHKeys(homeDir) {
  const vulnerableFiles = [];
  
  try {
    // Scan for files containing SSH private keys regardless of filename
    await searchForSSHKeysInFiles(homeDir, vulnerableFiles, 0, 2);
  } catch (error) {
    console.error('Error scanning for SSH keys:', error);
  }
  
  console.log('SSH keys scan found:', vulnerableFiles.length, 'files');
  return vulnerableFiles;
}

// Helper function to search for files containing SSH private keys
async function searchForSSHKeysInFiles(dir, results, currentDepth = 0, maxDepth = 2) {
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
            // Only recurse if we haven't reached max depth
            if (currentDepth < maxDepth) {
              await searchForSSHKeysInFiles(fullPath, results, currentDepth + 1, maxDepth);
            }
          }
        } else if (stats.isFile()) {
          // Skip files that are too large (> 1MB) or already in results
          if (stats.size > 1024 * 1024 || results.some(f => f.path === fullPath)) {
            continue;
          }
          
          // Only scan files without extensions for SSH key content
          const fileName = path.basename(fullPath);
          const hasExtension = path.extname(fileName) !== '';
          
          if (!hasExtension && await containsSSHPrivateKey(fullPath)) {
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

module.exports = { scanSSHKeys };