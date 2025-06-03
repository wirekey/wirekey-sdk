/**
 * Storage implementation for the JavaScript SDK
 * 
 * This module provides a storage implementation for the JavaScript SDK using
 * localStorage in the browser or a file-based storage in Node.js.
 */

// Add the storage functions to the wirekey namespace
window.wirekey = window.wirekey || {};

/**
 * Retrieves a value from storage
 * @param {string} key The key to retrieve
 * @returns {Promise<Uint8Array>} The value as a Uint8Array, or null if not found
 */
wirekey.storageGet = async function(key) {
    try {
        // In a browser environment, use localStorage
        if (typeof localStorage !== 'undefined') {
            const value = localStorage.getItem(key);
            if (value === null) {
                return null;
            }
            // Convert base64 string to Uint8Array
            const binaryString = atob(value);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes;
        }
        
        // In a Node.js environment, use the fs module
        if (typeof require !== 'undefined') {
            const fs = require('fs');
            const path = require('path');
            const storagePath = path.join(process.cwd(), '.wirekey-storage');
            
            // Create the storage directory if it doesn't exist
            if (!fs.existsSync(storagePath)) {
                fs.mkdirSync(storagePath, { recursive: true });
            }
            
            const filePath = path.join(storagePath, key);
            
            // Check if the file exists
            if (!fs.existsSync(filePath)) {
                return null;
            }
            
            // Read the file
            const buffer = fs.readFileSync(filePath);
            return new Uint8Array(buffer);
        }
        
        // If neither localStorage nor fs is available, return null
        console.error('No storage mechanism available');
        return null;
    } catch (error) {
        console.error('Error retrieving from storage:', error);
        return null;
    }
};

/**
 * Stores a value in storage
 * @param {string} key The key to store
 * @param {Uint8Array} value The value to store
 * @returns {Promise<boolean>} True if successful, false otherwise
 */
wirekey.storagePut = async function(key, value) {
    try {
        // In a browser environment, use localStorage
        if (typeof localStorage !== 'undefined') {
            // Convert Uint8Array to base64 string
            let binary = '';
            const bytes = new Uint8Array(value);
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            const base64 = btoa(binary);
            
            localStorage.setItem(key, base64);
            return true;
        }
        
        // In a Node.js environment, use the fs module
        if (typeof require !== 'undefined') {
            const fs = require('fs');
            const path = require('path');
            const storagePath = path.join(process.cwd(), '.wirekey-storage');
            
            // Create the storage directory if it doesn't exist
            if (!fs.existsSync(storagePath)) {
                fs.mkdirSync(storagePath, { recursive: true });
            }
            
            const filePath = path.join(storagePath, key);
            
            // Write the file
            fs.writeFileSync(filePath, Buffer.from(value));
            return true;
        }
        
        // If neither localStorage nor fs is available, return false
        console.error('No storage mechanism available');
        return false;
    } catch (error) {
        console.error('Error storing in storage:', error);
        return false;
    }
};

/**
 * Deletes a value from storage
 * @param {string} key The key to delete
 * @returns {Promise<boolean>} True if successful, false otherwise
 */
wirekey.storageDelete = async function(key) {
    try {
        // In a browser environment, use localStorage
        if (typeof localStorage !== 'undefined') {
            localStorage.removeItem(key);
            return true;
        }
        
        // In a Node.js environment, use the fs module
        if (typeof require !== 'undefined') {
            const fs = require('fs');
            const path = require('path');
            const storagePath = path.join(process.cwd(), '.wirekey-storage');
            const filePath = path.join(storagePath, key);
            
            // Check if the file exists
            if (!fs.existsSync(filePath)) {
                return true; // File doesn't exist, so it's already deleted
            }
            
            // Delete the file
            fs.unlinkSync(filePath);
            return true;
        }
        
        // If neither localStorage nor fs is available, return false
        console.error('No storage mechanism available');
        return false;
    } catch (error) {
        console.error('Error deleting from storage:', error);
        return false;
    }
};

/**
 * Checks if a key exists in storage
 * @param {string} key The key to check
 * @returns {Promise<boolean>} True if the key exists, false otherwise
 */
wirekey.storageExists = async function(key) {
    try {
        // In a browser environment, use localStorage
        if (typeof localStorage !== 'undefined') {
            return localStorage.getItem(key) !== null;
        }
        
        // In a Node.js environment, use the fs module
        if (typeof require !== 'undefined') {
            const fs = require('fs');
            const path = require('path');
            const storagePath = path.join(process.cwd(), '.wirekey-storage');
            const filePath = path.join(storagePath, key);
            
            return fs.existsSync(filePath);
        }
        
        // If neither localStorage nor fs is available, return false
        console.error('No storage mechanism available');
        return false;
    } catch (error) {
        console.error('Error checking if key exists in storage:', error);
        return false;
    }
};