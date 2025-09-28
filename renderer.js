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

        document.getElementById('addPathBtn').addEventListener('click', () => {
            this.addCustomPath();
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
            keyInput.value = ''; // Clear the input for security
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

    async addCustomPath() {
        if (!this.encryptionKey) {
            this.showMessage('Please set an encryption key first', 'error');
            return;
        }

        try {
            const directoryPath = await window.electronAPI.selectDirectory();
            if (directoryPath) {
                const fileInfo = await window.electronAPI.addCustomPath(directoryPath);
                this.files.push(fileInfo);
                this.renderFileTable();
                this.showMessage('Custom path added successfully', 'success');
            }
        } catch (error) {
            this.showMessage('Error adding custom path: ' + error.message, 'error');
        }
    }

    async encryptFile(filePath) {
        if (!this.encryptionKey) {
            this.showMessage('Please set an encryption key first', 'error');
            return;
        }

        try {
            const result = await window.electronAPI.encryptFile(filePath, this.encryptionKey);
            if (result.success) {
                this.showMessage('File encrypted successfully', 'success');
                // Update the file list to reflect the change
                await this.scanVulnerableLocations();
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
                await this.scanVulnerableLocations();
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
        // Shorten the path for display
        const homeDir = process.env.HOME || process.env.USERPROFILE;
        if (fullPath.startsWith(homeDir)) {
            return '~' + fullPath.substring(homeDir.length);
        }
        return fullPath;
    }

    escapePath(path) {
        // Escape path for use in HTML attributes
        return path.replace(/'/g, "\\'");
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
document.addEventListener('DOMContentLoaded', () => {
    window.app = new KeyCypherApp();
});