class KeyCypherApp {
    constructor() {
        this.encryptionKey = '';
        this.files = [];
        this.initEventListeners();
    }

    initEventListeners() {
        document.getElementById('setKey').addEventListener('click', () => {
            this.setEncryptionKey();
        });

        document.getElementById('scanBtn').addEventListener('click', () => {
            this.scanVulnerableLocations();
        });

        document.getElementById('addFileBtn').addEventListener('click', () => {
            this.addFile();
        });

        document.getElementById('addDirectoryBtn').addEventListener('click', () => {
            this.addDirectory();
        });

        document.getElementById('refreshBtn').addEventListener('click', () => {
            this.refreshFileList();
        });

        document.getElementById('backupBtn').addEventListener('click', () => {
            this.createBackup();
        });

        // Allow Enter key to set encryption key
        document.getElementById('encryptionKey').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.setEncryptionKey();
            }
        });
    }

    setEncryptionKey() {
        const keyInput = document.getElementById('encryptionKey');
        this.encryptionKey = keyInput.value.trim();
        
        if (this.encryptionKey) {
            this.showMessage('Encryption key set successfully', 'success');
            // Don't clear the input so it can be used for decryption
        } else {
            this.showMessage('Please enter an encryption key', 'error');
        }
    }

    async scanVulnerableLocations() {
        try {
            this.showMessage('Scanning for vulnerable files in background...', 'info');
            
            // Start background scan - don't await, let it run in background
            window.electronAPI.startBackgroundScan();
            
            // Don't block the UI - user can continue working
            this.showMessage('Background scan started. Files will be added as found.', 'success');
        } catch (error) {
            this.showMessage('Error starting scan: ' + error.message, 'error');
        }
    }

    // Method to add files from background scan
    addFilesFromBackgroundScan(newFiles) {
        if (!newFiles || newFiles.length === 0) return;
        
        const existingPaths = new Set(this.files.map(file => file.path.replace(/\\/g, '/')));
        let newFilesCount = 0;
        
        newFiles.forEach(file => {
            const normalizedPath = file.path.replace(/\\/g, '/');
            if (!existingPaths.has(normalizedPath)) {
                this.files.push(file);
                existingPaths.add(normalizedPath);
                newFilesCount++;
            }
        });
        
        if (newFilesCount > 0) {
            this.renderFileTable();
            this.showMessage(`Added ${newFilesCount} new files from background scan`, 'success');
        }
    }

    async addFile() {
        try {
            const selectedFile = await window.electronAPI.selectFile();
            if (selectedFile) {
                const fileInfo = await window.electronAPI.addCustomPath(selectedFile);
                this.files.push(fileInfo);
                this.renderFileTable();
                this.showMessage('File added successfully', 'success');
            }
        } catch (error) {
            this.showMessage('Error adding file: ' + error.message, 'error');
        }
    }

    async addDirectory() {
        try {
            const selectedDirectory = await window.electronAPI.selectDirectory();
            if (selectedDirectory) {
                const fileInfo = await window.electronAPI.addCustomPath(selectedDirectory);
                this.files.push(fileInfo);
                this.renderFileTable();
                this.showMessage('Directory added successfully', 'success');
            }
        } catch (error) {
            this.showMessage('Error adding directory: ' + error.message, 'error');
        }
    }

    async encryptFile(filePath) {
        if (!this.encryptionKey) {
            this.showMessage('Please set an encryption key first', 'error');
            return;
        }

        try {
            console.log('Attempting to encrypt file:', filePath);
            const result = await window.electronAPI.encryptFile(filePath, this.encryptionKey);
            if (result.success) {
                this.showMessage('File encrypted successfully', 'success');
                // Update the file list to reflect the change
                await this.updateFileAfterOperation(filePath, result.encryptedPath, true);
            } else {
                // Show user-friendly error message
                let errorMessage = 'Encryption failed';
                if (result.error) {
                    errorMessage = 'Encryption failed: ' + result.error;
                }
                this.showMessage(errorMessage, 'error');
            }
        } catch (error) {
            this.showMessage('Encryption error: ' + error.message, 'error');
        }
    }

    async decryptFile(filePath) {
        if (!this.encryptionKey) {
            this.showMessage('Please set an encryption key first', 'error');
            return;
        }

        try {
            const result = await window.electronAPI.decryptFile(filePath, this.encryptionKey);
            if (result.success) {
                this.showMessage('File decrypted successfully', 'success');
                // Update the file list to reflect the change
                await this.updateFileAfterOperation(filePath, result.decryptedPath, false);
            } else {
                // Show user-friendly error message
                let errorMessage = 'Decryption failed';
                if (result.error && result.error.includes('BAD_DECRYPT')) {
                    errorMessage = 'Invalid encryption key. Please check your key and try again.';
                } else if (result.error) {
                    errorMessage = 'Decryption failed: ' + result.error;
                }
                this.showMessage(errorMessage, 'error');
            }
        } catch (error) {
            this.showMessage('Decryption error: ' + error.message, 'error');
        }
    }

    async removeFile(filePath) {
        try {
            const result = await window.electronAPI.removeFileFromList(filePath);
            if (result.success) {
                // Remove from local file list
                const normalizePath = (path) => path.replace(/\\/g, '/');
                const normalizedFilePath = normalizePath(filePath);
                
                this.files = this.files.filter(file => {
                    const normalizedCurrentPath = normalizePath(file.path);
                    return normalizedCurrentPath !== normalizedFilePath;
                });
                
                this.renderFileTable();
                this.showMessage('File removed from list', 'success');
            } else {
                this.showMessage('Error removing file: ' + result.error, 'error');
            }
        } catch (error) {
            this.showMessage('Error removing file: ' + error.message, 'error');
        }
    }

    async renderFileTable() {
        const tableBody = document.getElementById('fileTableBody');
        
        if (this.files.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" class="loading">No files found</td></tr>';
            return;
        }

        // Remove duplicates and sort alphabetically
        const uniqueFiles = this.removeDuplicates(this.files);
        const sortedFiles = this.sortFilesAlphabetically(uniqueFiles);

        // Check file status for each file
        const filesWithStatus = await Promise.all(
            sortedFiles.map(async (file) => {
                try {
                    const status = await window.electronAPI.checkFileStatus(file.path);
                    return { ...file, status };
                } catch (error) {
                    console.log('Error checking file status:', error);
                    return { ...file, status: { exists: false, status: 'ERROR', hasConflict: false } };
                }
            })
        );

        tableBody.innerHTML = filesWithStatus.map(file => {
            const statusClass = this.getStatusClass(file);
            const statusText = this.getStatusText(file);
            const hasConflict = file.status.hasConflict;
            const isMissing = file.status.status === 'MISSING';
            const buttonsDisabled = (hasConflict || isMissing) ? 'disabled' : '';
            
            return `
            <tr>
                <td>${this.formatPath(file.path)}</td>
                <td>
                    <span class="file-type type-${file.type}">
                        ${file.type.toUpperCase()}
                    </span>
                </td>
                <td>
                    <span class="${statusClass}">
                        ${statusText}
                    </span>
                </td>
                <td class="actions">
                    <button class="action-btn btn-primary"
                            onclick="app.encryptFile('${this.escapePath(file.path)}')"
                            ${file.encrypted ? 'disabled' : ''} ${buttonsDisabled}>
                        Encrypt
                    </button>
                    <button class="action-btn btn-secondary"
                            onclick="app.decryptFile('${this.escapePath(file.path)}')"
                            ${!file.encrypted ? 'disabled' : ''} ${buttonsDisabled}>
                        Decrypt
                    </button>
                    <button class="action-btn btn-info" onclick="app.openInExplorer('${this.escapePath(file.path)}')">
                        Open
                    </button>
                    <button class="action-btn btn-danger" onclick="app.removeFile('${this.escapePath(file.path)}')">
                        Remove
                    </button>
                </td>
            </tr>
        `}).join('');
    }

    removeDuplicates(files) {
        const seen = new Set();
        return files.filter(file => {
            const normalizedPath = file.path.replace(/\\/g, '/').toLowerCase();
            if (seen.has(normalizedPath)) {
                return false;
            }
            seen.add(normalizedPath);
            return true;
        });
    }

    sortFilesAlphabetically(files) {
        return files.sort((a, b) => {
            const pathA = a.path.replace(/\\/g, '/').toLowerCase();
            const pathB = b.path.replace(/\\/g, '/').toLowerCase();
            return pathA.localeCompare(pathB);
        });
    }

    getStatusClass(file) {
        if (file.status.status === 'MISSING') {
            return 'status-missing';
        } else if (file.status.status === 'CONFLICT') {
            return 'status-conflict';
        } else {
            return file.encrypted ? 'status-encrypted' : 'status-decrypted';
        }
    }

    getStatusText(file) {
        if (file.status.status === 'MISSING') {
            return 'MISSING';
        } else if (file.status.status === 'CONFLICT') {
            return 'CONFLICT';
        } else {
            return file.encrypted ? 'ENCRYPTED' : 'DECRYPTED';
        }
    }

    formatPath(fullPath) {
        // Normalize path to use forward slashes consistently
        return fullPath.replace(/\\/g, '/');
    }

    escapePath(path) {
        // Escape path for use in HTML attributes
        // Replace backslashes with forward slashes and escape quotes
        return path.replace(/\\/g, '/').replace(/'/g, "\\'");
    }

    async updateFileAfterOperation(oldPath, newPath, isEncrypted) {
        // Update the file in the local list and persistent storage
        console.log('Updating file from:', oldPath, 'to:', newPath, 'encrypted:', isEncrypted);
        
        // Normalize paths for comparison (handle both / and \ separators)
        const normalizePath = (path) => path.replace(/\\/g, '/');
        const normalizedOldPath = normalizePath(oldPath);
        
        // Update local file list - remove old path (handle both separators)
        this.files = this.files.filter(file => {
            const normalizedFilePath = normalizePath(file.path);
            return normalizedFilePath !== normalizedOldPath;
        });
        
        // Add the new file to the list
        const fileType = newPath.endsWith('_cypheredd.zip') ? 'directory' :
                        newPath.includes('_cyphered') ? 'file' : 'file';
        
        this.files.push({
            path: newPath,
            type: fileType,
            encrypted: isEncrypted
        });
        
        // Update persistent storage
        try {
            await window.electronAPI.updateFileList(oldPath, newPath, isEncrypted);
        } catch (error) {
            console.log('Error updating persistent storage:', error);
        }
        
        this.renderFileTable();
        console.log('Successfully updated file in table');
    }

    async openInExplorer(filePath) {
        try {
            const result = await window.electronAPI.openFileInExplorer(filePath);
            if (result.success) {
                this.showMessage('Opened file location in explorer', 'success');
            } else {
                this.showMessage('Error opening file location: ' + result.error, 'error');
            }
        } catch (error) {
            this.showMessage('Error opening file location: ' + error.message, 'error');
        }
    }

    async refreshFileList() {
        try {
            this.showLoading();
            // Reload files from persistent storage and update status
            const files = await window.electronAPI.loadFilesOnStartup();
            if (files && files.length > 0) {
                // Re-detect file types based on suffixes for encrypted files
                this.files = files.map(file => ({
                    ...file,
                    type: file.path.endsWith('_cypheredd.zip') ? 'directory' :
                          file.path.includes('_cyphered') ? 'file' : file.type
                }));
                await this.renderFileTable();
                this.showMessage('File list refreshed', 'success');
            } else {
                this.files = [];
                this.renderFileTable();
                this.showMessage('No files found in list', 'info');
            }
        } catch (error) {
            this.showMessage('Error refreshing file list: ' + error.message, 'error');
        }
    }

    showMessage(message, type) {
        const messageArea = document.getElementById('messageArea');
        messageArea.innerHTML = `<div class="${type}">${message}</div>`;
        
        // Auto-hide success messages after 3 seconds
        if (type === 'success') {
            setTimeout(() => {
                if (messageArea.innerHTML.includes(message)) {
                    messageArea.innerHTML = '';
                }
            }, 3000);
        }
    }

    showLoading() {
        const tableBody = document.getElementById('fileTableBody');
        tableBody.innerHTML = '<tr><td colspan="4" class="loading">Scanning...</td></tr>';
    }

    async createBackup() {
        try {
            this.showMessage('Creating backup...', 'info');
            const result = await window.electronAPI.createBackup();
            
            if (result.success) {
                this.showMessage(`Backup created successfully: ${result.backupPath}`, 'success');
            } else {
                this.showMessage('Backup failed: ' + result.error, 'error');
            }
        } catch (error) {
            this.showMessage('Error creating backup: ' + error.message, 'error');
        }
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', async () => {
    window.app = new KeyCypherApp();
    
    // Load persistent files automatically on startup
    try {
        const files = await window.electronAPI.loadFilesOnStartup();
        if (files && files.length > 0) {
            window.app.files = files;
            window.app.renderFileTable();
            console.log('Loaded', files.length, 'files on startup');
        }
    } catch (error) {
        console.log('Error loading files on startup:', error);
    }
    
    // Set up background scan listeners
    window.electronAPI.onBackgroundScanUpdate((event, files) => {
        window.app.addFilesFromBackgroundScan(files);
    });
    
    window.electronAPI.onBackgroundScanComplete((event, result) => {
        if (result.success) {
            window.app.showMessage('Background scan completed', 'success');
        } else {
            window.app.showMessage('Background scan failed: ' + result.error, 'error');
        }
    });
});