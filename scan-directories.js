const fs = require('fs');
const fsPromises = require('fs').promises;
const path = require('path');

// Process 1: Scan vulnerable directories
async function scanVulnerableDirectories(homeDir) {
  const vulnerableFiles = [];
  
  const scanDirectories = [
    {
      dir: path.join(homeDir, '.aws'),
      files: ['credentials']
    },
    {
      dir: path.join(homeDir, '.ssh'),
      files: ['id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys', 'known_hosts', 'config']
    },
    {
      dir: path.join(homeDir, '.kube'),
      files: ['config']
    },
    {
      dir: path.join(homeDir, '.docker'),
      files: ['config.json']
    },
    {
      dir: path.join(homeDir, '.azure'),
      files: ['accessTokens.json', 'azureProfile.json']
    },
    {
      dir: path.join(homeDir, '.config', 'gcloud'),
      files: ['access_tokens.db', 'credentials.db']
    },
    {
      dir: path.join(homeDir, '.config', 'git'),
      files: ['credentials']
    },
    {
      dir: path.join(homeDir, '.config', 'gh'),
      files: ['hosts.yml', 'config.yml']
    }
  ];
  
  for (const scanDir of scanDirectories) {
    if (fs.existsSync(scanDir.dir) && fs.statSync(scanDir.dir).isDirectory()) {
      for (const fileName of scanDir.files) {
        const filePath = path.join(scanDir.dir, fileName);
        if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
          vulnerableFiles.push({
            path: filePath,
            type: 'file',
            encrypted: filePath.includes('_cyphered')
          });
          
          // Special handling for SSH config files to extract IdentityFile paths
          if (fileName === 'config') {
            await extractIdentityFilesFromSSHConfig(filePath, vulnerableFiles);
          }
        }
      }
    }
  }
  
  console.log('Directory scan found:', vulnerableFiles.length, 'files');
  return vulnerableFiles;
}

// Helper function to extract IdentityFile paths from SSH config
async function extractIdentityFilesFromSSHConfig(configPath, vulnerableFiles) {
  try {
    const configContent = await fsPromises.readFile(configPath, 'utf8');
    const lines = configContent.split('\n');
    
    for (const line of lines) {
      const trimmedLine = line.trim();
      
      // Skip comments and empty lines
      if (trimmedLine.startsWith('#') || trimmedLine === '') {
        continue;
      }
      
      // Look for IdentityFile directives
      if (trimmedLine.toLowerCase().startsWith('identityfile')) {
        const parts = trimmedLine.split(/\s+/);
        if (parts.length >= 2) {
          let identityPath = parts[1];
          
          // Handle quoted paths
          if (identityPath.startsWith('"') && identityPath.endsWith('"')) {
            identityPath = identityPath.slice(1, -1);
          } else if (identityPath.startsWith("'") && identityPath.endsWith("'")) {
            identityPath = identityPath.slice(1, -1);
          }
          
          // Expand ~ to home directory
          if (identityPath.startsWith('~')) {
            const homeDir = process.env.HOME || process.env.USERPROFILE;
            identityPath = path.join(homeDir, identityPath.slice(1));
          }
          
          // Resolve relative paths relative to SSH config directory
          if (!path.isAbsolute(identityPath)) {
            const configDir = path.dirname(configPath);
            identityPath = path.resolve(configDir, identityPath);
          }
          
          // Check if the identity file exists and add it to vulnerable files
          if (fs.existsSync(identityPath) && fs.statSync(identityPath).isFile()) {
            vulnerableFiles.push({
              path: identityPath,
              type: 'file',
              encrypted: identityPath.includes('_cyphered')
            });
          }
        }
      }
    }
  } catch (error) {
    console.error('Error parsing SSH config:', error);
  }
}

module.exports = { scanVulnerableDirectories };