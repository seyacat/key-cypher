const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');

// Process 3: Scan for PEM and PPK files recursively in user directory
async function scanPemPpkFiles(homeDir) {
  const vulnerableFiles = [];
  
  try {
    // Recursively search for .pem and .ppk files
    await searchForFileTypes(homeDir, ['.pem', '.ppk'], vulnerableFiles);
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

module.exports = { scanPemPpkFiles };