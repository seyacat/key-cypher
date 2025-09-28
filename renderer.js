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
        if (!this.encryptionKey) {
            this.showMessage('Please set an encryption key first', 'error');
            return;
        }

        try {
            this.showLoading();
            const files = await window.electronAPI.scanVulnerableLocations();
            this.files = files;
            this.renderFileTable();
            this.showMessage(`Found ${files.length} vulnerable locations`, 'success');
        } catch (error) {
            this.showMessage('Error scanning locations: ' + error.message, 'error');
        }
    }

    async addFile() {
        if (!this.encryptionKey) {
            this.showMessage('Please set an encryption key first', 'error');
            return;
        }

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
        if (!this.encryptionKey) {
            this.showMessage('Please set an encryption key first', 'error');
            return;
        }

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
                this.showMessage('Encryption failed: ' + result.error, 'error');
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
                this.showMessage('Decryption failed: ' + result.error, 'error');
            }
        } catch (error) {
            this.showMessage('Decryption error: ' + error.message, 'error');
        }
    }

    renderFileTable() {
        const tableBody = document.getElementById('fileTableBody');
        
        if (this.files.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" class="loading">No files found</td></tr>';
            return;
        }

        tableBody.innerHTML = this.files.map(file => `
            <tr>
                <td>${this.formatPath(file.path)}</td>
                <td>
                    <span class="file-type type-${file.type}">
                        ${file.type.toUpperCase()}
                    </span>
                </td>
                <td>
                    <span class="status-${file.encrypted ? 'encrypted' : 'decrypted'}">
                        ${file.encrypted ? 'ENCRYPTED' : 'DECRYPTED'}
                    </span>
                </td>
                <td class="actions">
                    ${!file.encrypted ? 
                        `<button class="action-btn btn-primary" onclick="app.encryptFile('${this.escapePath(file.path)}')">
                            Encrypt
                        </button>` : 
                        `<button class="action-btn btn-secondary" onclick="app.decryptFile('${this.escapePath(file.path)}')">
                            Decrypt
                        </button>`
                    }
                </td>
            </tr>
        `).join('');
    }

    formatPath(fullPath) {
        // For display purposes, we'll just show the full path
        // In a real implementation, we could get the home directory from main process
        return fullPath;
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
        const fileType = newPath.endsWith('_cyphered.zip') ? 'directory' :
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
});