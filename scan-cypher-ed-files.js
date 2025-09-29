const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');

// Process 4: Scan for files with "cyphered" in filename (previously encrypted files)
async function scanCypheredFiles(homeDir) {
  const cypheredFiles = [];
  
  try {
    // Recursively search for files with "cyphered" in filename
    await searchForCypheredFiles(homeDir, cypheredFiles);
  } catch (error) {
    console.error('Error scanning for cyphered files:', error);
  }
  
  console.log('Cyphered files scan found:', cypheredFiles.length, 'files');
  return cypheredFiles;
}

// Helper function to search for files with "cyphered" in filename
async function searchForCypheredFiles(dir, results) {
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
            await searchForCypheredFiles(fullPath, results);
          }
        } else if (stats.isFile()) {
          // Check if filename contains "cyphered" (case insensitive)
          if (item.toLowerCase().includes('cyphered')) {
            results.push({
              path: fullPath,
              type: 'file',
              encrypted: true,
              detectedBy: 'cyphered_filename'
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

module.exports = { scanCypheredFiles };