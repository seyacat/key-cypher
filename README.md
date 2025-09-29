# Key Cypher - File Encryption Tool

An Electron application for scanning and encrypting vulnerable credential files in common locations like `.ssh`, `.aws`, and GitHub configuration files.

## Features

- **Scan Vulnerable Locations**: Automatically scans for common credential file locations
- **File Encryption/Decryption**: Encrypts and decrypts files using AES encryption
- **Directory Support**: Handles both files and directories (directories are zipped before encryption)
- **Custom Paths**: Add custom file paths to scan and encrypt
- **Encryption Status Tracking**: Shows which files are encrypted or decrypted
- **Secure Key Management**: Uses user-provided encryption keys
- **Background Scanning**: Continuous scanning in the background for new vulnerable files
- **File Backup**: Create encrypted backups of all scanned files
- **Conflict Detection**: Automatically detects file conflicts between encrypted and original versions
- **Persistent Storage**: Maintains file list across application sessions

## Vulnerable Locations Scanned

- `~/.ssh/` - SSH keys, configuration, and identity files
- `~/.aws/` - AWS credentials and configuration
- `~/.kube/` - Kubernetes configuration
- `~/.docker/` - Docker configuration
- `~/.azure/` - Azure credentials and profiles
- `~/.config/gcloud/` - Google Cloud credentials
- `~/.config/git/` - Git credential storage
- `~/.config/gh/` - GitHub CLI configuration
- `~/.git-credentials` - Git credential storage
- PEM and PPK private key files

## File Operations

- **Encryption**: Files are encrypted using AES-256-CBC with user-provided keys
- **Decryption**: Secure decryption with automatic file restoration
- **Directory Handling**: Directories are compressed to ZIP format before encryption
- **File Management**: Automatic detection of encrypted files by naming pattern
- **Conflict Resolution**: Identifies and warns about file conflicts

## Security Features

- **No Key Storage**: Encryption keys are never stored - entered each session
- **Secure Deletion**: Original files are deleted after successful encryption/decryption
- **Rollback Protection**: Automatic cleanup on operation failures
- **Permission Checking**: Validates file permissions before operations
- **Process Isolation**: File operations run in secure main process

## Technical Architecture

- **Cross-Platform**: Built with Electron for Windows, macOS, and Linux compatibility
- **Modular Scanning**: Separate modules for directories, single files, and PEM/PPK files
- **AES-256-CBC**: Industry-standard encryption via Node.js crypto module
- **IPC Communication**: Secure data transfer between main and renderer processes
- **Persistent Data**: File metadata stored in application user data directory
