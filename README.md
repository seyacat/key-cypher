# Key Cypher - File Encryption Tool

An Electron application for scanning and encrypting vulnerable credential files in common locations like `.ssh`, `.aws`, and GitHub configuration files.

## Features

- **Scan Vulnerable Locations**: Automatically scans for common credential file locations
- **File Encryption/Decryption**: Encrypts and decrypts files using AES encryption
- **Directory Support**: Handles both files and directories (directories are zipped before encryption)
- **Custom Paths**: Add custom file paths to scan and encrypt
- **Encryption Status Tracking**: Shows which files are encrypted or decrypted
- **Secure Key Management**: Uses user-provided encryption keys

## Vulnerable Locations Scanned

- `~/.ssh/` - SSH keys and configuration
- `~/.aws/` - AWS credentials and configuration  
- `~/.git-credentials` - Git credential storage
- `~/.config/gh/hosts.yml` - GitHub CLI configuration

## Installation

1. Install dependencies:
```bash
npm install
```

2. Run the application:
```bash
npm start
```

For development with DevTools:
```bash
npm run dev
```

## Usage

1. **Set Encryption Key**: Enter your encryption key in the top input field and click "Set Key"
2. **Scan Locations**: Click "Scan Vulnerable Locations" to find files that may contain credentials
3. **Add Custom Paths**: Use "Add Custom Path" to include additional files or directories
4. **Encrypt/Decrypt**: Use the action buttons in the table to encrypt or decrypt files

## File Naming Convention

- Encrypted files have the suffix `_cyphered` added to their filename
- Encrypted directories are zipped and named with `_cyphered.zip` suffix
- The application automatically detects encrypted files by this naming pattern

## Security Notes

- The encryption key is never stored - you must enter it each session
- Original files are deleted after successful encryption/decryption
- Use a strong, unique encryption key for maximum security
- Always test decryption with a non-critical file first

## Technical Details

- Built with Electron for cross-platform compatibility
- Uses AES-256-CBC encryption via Node.js native crypto module
- File operations are performed securely in the main process
- IPC communication ensures secure data transfer between processes

## Development

The application consists of:
- `main.js` - Main Electron process with file operations and IPC handlers
- `preload.js` - Secure bridge for renderer process communication
- `index.html` - User interface
- `renderer.js` - Frontend logic and UI interactions
