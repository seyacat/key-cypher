const fs = require('fs');
const path = require('path');

// Process: Scan for .env* files in user home directory
async function scanEnvFiles(homeDir) {
    const vulnerableFiles = [];
    
    try {
        console.log('Scanning for .env* files in:', homeDir);
        
        // Recursively scan the home directory for .env* files
        await scanDirectoryForEnvFiles(homeDir, vulnerableFiles);
        
        console.log('Env files scan found:', vulnerableFiles.length, 'files');
        return vulnerableFiles;
    } catch (error) {
        console.error('Error scanning for .env files:', error);
        return vulnerableFiles;
    }
}

// Recursive function to scan directory for .env* files
async function scanDirectoryForEnvFiles(dirPath, vulnerableFiles) {
    try {
        const items = fs.readdirSync(dirPath);
        
        for (const item of items) {
            const fullPath = path.join(dirPath, item);
            
            try {
                const stat = fs.statSync(fullPath);
                
                if (stat.isDirectory()) {
                    // Skip certain directories to avoid permission issues and system folders
                    const skipDirs = [
                        'node_modules', '.git', '.vscode', '.idea', 
                        'Library', 'Applications', 'System', 'tmp',
                        'var', 'etc', 'usr', 'bin', 'sbin', 'opt'
                    ];
                    
                    const baseName = path.basename(fullPath);
                    if (!skipDirs.includes(baseName) && 
                        !baseName.startsWith('.') || baseName === '.config') {
                        await scanDirectoryForEnvFiles(fullPath, vulnerableFiles);
                    }
                } else if (stat.isFile()) {
                    // Check if file matches .env* pattern
                    const fileName = path.basename(fullPath);
                    if (fileName.startsWith('.env')) {
                        vulnerableFiles.push({
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
        // Skip directories we can't read
        console.log('Cannot access directory:', dirPath, error.message);
    }
}

module.exports = { scanEnvFiles };