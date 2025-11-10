const crypto = require('crypto');

class EncryptionUtil {
    constructor() {
        this.algorithm = 'aes-256-gcm';
        this.key = this.deriveKey(process.env.ENCRYPTION_SECRET || 'fallback-secret-key-change-in-production');
        this.ivLength = 16;
        this.authTagLength = 16;
    }

    // Derive a consistent key from a secret
    deriveKey(secret) {
        return crypto.createHash('sha256').update(secret).digest();
    }

    // Encrypt data
    encrypt(data) {
        try {
            if (typeof data !== 'string') {
                data = JSON.stringify(data);
            }

            const iv = crypto.randomBytes(this.ivLength);
            const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
            
            let encrypted = cipher.update(data, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            const authTag = cipher.getAuthTag();
            
            // Combine IV + authTag + encrypted data
            const result = Buffer.concat([
                iv,
                authTag,
                Buffer.from(encrypted, 'hex')
            ]).toString('base64');

            return result;
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Failed to encrypt data');
        }
    }

    // Decrypt data
    decrypt(encryptedData) {
        try {
            const buffer = Buffer.from(encryptedData, 'base64');
            
            // Extract components
            const iv = buffer.slice(0, this.ivLength);
            const authTag = buffer.slice(this.ivLength, this.ivLength + this.authTagLength);
            const encrypted = buffer.slice(this.ivLength + this.authTagLength);
            
            const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(encrypted.toString('hex'), 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            // Try to parse as JSON, return as string if it fails
            try {
                return JSON.parse(decrypted);
            } catch {
                return decrypted;
            }
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Failed to decrypt data');
        }
    }

    // Hash data (one-way)
    hash(data, salt = null) {
        try {
            const dataString = typeof data === 'string' ? data : JSON.stringify(data);
            const hash = crypto.createHash('sha256');
            
            if (salt) {
                hash.update(dataString + salt);
            } else {
                hash.update(dataString);
            }
            
            return hash.digest('hex');
        } catch (error) {
            console.error('Hashing error:', error);
            throw new Error('Failed to hash data');
        }
    }

    // Generate random token
    generateRandomToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    // Generate secure random number
    generateSecureRandomNumber(min, max) {
        const range = max - min;
        const bytes = Math.ceil(Math.log2(range) / 8);
        const maxVal = Math.pow(2, bytes * 8);
        
        let randomNumber;
        do {
            const randomBytes = crypto.randomBytes(bytes);
            randomNumber = randomBytes.readUIntBE(0, bytes);
        } while (randomNumber >= maxVal - (maxVal % range));
        
        return min + (randomNumber % range);
    }

    // Verify encrypted data integrity
    verifyIntegrity(encryptedData, originalHash) {
        try {
            const decrypted = this.decrypt(encryptedData);
            const currentHash = this.hash(decrypted);
            return currentHash === originalHash;
        } catch (error) {
            return false;
        }
    }

    // Create HMAC signature
    createHMAC(data, secret = null) {
        const hmac = crypto.createHmac('sha256', secret || this.key);
        hmac.update(typeof data === 'string' ? data : JSON.stringify(data));
        return hmac.digest('hex');
    }

    // Verify HMAC signature
    verifyHMAC(data, signature, secret = null) {
        const expectedSignature = this.createHMAC(data, secret);
        return this.constantTimeCompare(signature, expectedSignature);
    }

    // Constant-time comparison to prevent timing attacks
    constantTimeCompare(a, b) {
        if (a.length !== b.length) {
            return false;
        }
        
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        return result === 0;
    }

    // Generate key pair for asymmetric encryption (if needed)
    generateKeyPair() {
        return crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
    }
}

// Create singleton instance
const encryptionUtil = new EncryptionUtil();

// Export utility functions
module.exports = {
    encrypt: encryptionUtil.encrypt.bind(encryptionUtil),
    decrypt: encryptionUtil.decrypt.bind(encryptionUtil),
    encryptData: encryptionUtil.encrypt.bind(encryptionUtil), // alias
    decryptData: encryptionUtil.decrypt.bind(encryptionUtil), // alias
    hash: encryptionUtil.hash.bind(encryptionUtil),
    generateRandomToken: encryptionUtil.generateRandomToken.bind(encryptionUtil),
    generateSecureRandomNumber: encryptionUtil.generateSecureRandomNumber.bind(encryptionUtil),
    verifyIntegrity: encryptionUtil.verifyIntegrity.bind(encryptionUtil),
    createHMAC: encryptionUtil.createHMAC.bind(encryptionUtil),
    verifyHMAC: encryptionUtil.verifyHMAC.bind(encryptionUtil),
    constantTimeCompare: encryptionUtil.constantTimeCompare.bind(encryptionUtil),
    generateKeyPair: encryptionUtil.generateKeyPair.bind(encryptionUtil),
    
    // Class for extension
    EncryptionUtil
};