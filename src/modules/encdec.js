const { pbkdf2, randomBytes, createHash, createCipheriv, createHmac, createDecipheriv, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');
const { isIPv6, isIPv4 } = require('node:net')

const config = require('./config');

const pbkdf2_promise = promisify(pbkdf2);
const randomBytes_promise = promisify(randomBytes);

/**
 * Gets the client Session ID for IPv4 and IPv6
 * @param {string} ipAddress 
 * @returns 
 */
const getSessionId = (ipAddress) => {
    let sum = 0;
    if (ipAddress === '::1') {
        ipAddress = '127.0.0.1';
    }
    if (isIPv6(ipAddress)) {
        sum = ipAddress.replace(/\D/g,'').reduce((acc, val) => acc + parseInt(val), 0);
    }
    if (isIPv4(ipAddress)) {
        sum = ipAddress.split('.').reduce((acc, val) => acc + parseInt(val), 0);
    }
    return createHash('sha256').update(ipAddress + '<>' + sum).digest('hex').slice(0, 32);
};

/**
 * PBKDF2 Encryption
 * @param {string} data 
 * @param {string} sharedKey 
 * @param {string} [cipher='aes-256-gcm'] 
 * @returns {Promise<string>}
 */
const encryptData = async (data, sharedKey, cipher = 'aes-256-gcm') => {
    if (typeof data !== 'string' || typeof sharedKey !== 'string') {
        throw new TypeError('Data and shared key must be strings');
    }
    if (!config.encryption.algorithms.includes(cipher)) {
        throw new TypeError(`Unsupported cipher. Supported ciphers are: ${config.encryption.algorithms.join(', ')}`);
    }
    try {
        const salt = await randomBytes_promise(32);
        const iv = await randomBytes_promise(cipher.endsWith('gcm') ? 12 : 16);
        const key = await pbkdf2_promise(sharedKey, salt, 200000, 32, 'sha512');
        const cipherIv = createCipheriv(cipher, key, iv);
        let encryptedData = cipherIv.update(data, 'utf8', 'base64');
        encryptedData += cipherIv.final('base64');
        let authTag;
        if (cipher.endsWith('gcm')) {
            authTag = cipherIv.getAuthTag();
        } else {
            const hmac = createHmac('sha256', key);
            hmac.update(Buffer.from(encryptedData, 'base64'));
            authTag = hmac.digest();
        }
        return `${salt.toString('base64')}:${iv.toString('base64')}:${authTag.toString('base64')}:${encryptedData}`;
    } catch (err) {
        if (err instanceof TypeError) {
            throw err;
        }
        throw new Error(`Encryption failed: ${err.message}`);
    }
};

/**
 * PBKDF2 Decryption
 * @param {string} encrypted 
 * @param {string} sharedKey 
 * @returns {Promise<string>}
 */
const decryptData = async (encrypted, sharedKey) => {
    try {
        // Split and decode Base64 encoded components
        const [salt, iv, authTag, encryptedData] = encrypted.split(':').map(part => Buffer.from(part, 'base64'));

        // Determine the cipher mode based on IV length
        const cipher = iv.length === 12 ? 'aes-256-gcm' : 'aes-256-cbc';

        // Derive the key using PBKDF2
        const key = await pbkdf2_promise(sharedKey, salt, 200000, 32, 'sha512');

        if (cipher === 'aes-256-gcm') {
            // Initialize decipher for AES-GCM
            const decipher = createDecipheriv(cipher, key, iv);
            decipher.setAuthTag(authTag);

            // Decrypt the data
            let decryptedData = decipher.update(encryptedData);
            decryptedData = Buffer.concat([decryptedData, decipher.final()]);

            return decryptedData.toString('utf8');
        } else if (cipher === 'aes-256-cbc') {
            // Initialize decipher for AES-CBC
            const decipher = createDecipheriv(cipher, key, iv);

            // Decrypt the data
            let decryptedData = decipher.update(encryptedData);
            decryptedData = Buffer.concat([decryptedData, decipher.final()]);

            // Create HMAC to verify the authenticity of the data
            const hmac = createHmac('sha256', key);
            hmac.update(Buffer.concat([iv, encryptedData]));
            const computedAuthTag = hmac.digest();

            // Verify HMAC
            if (!timingSafeEqual(authTag, computedAuthTag)) {
                throw new Error('Authentication failed. The data may have been tampered with.');
            }

            return decryptedData.toString('utf8');
        } else {
            throw new Error('Unsupported cipher mode.');
        }
    } catch (err) {
        throw new Error(`Decryption failed: ${err.message}`);
    }
};

module.exports = {
    getSessionId,
    decryptData,
    encryptData,
};