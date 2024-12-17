const { networkInterfaces } = require("node:os");
const { logError } = require("./logging");

const config = require('./config');

/**
 * Returns the active channel port set in config
 * @returns number
 */
const getServerPort = () => {
    let port = 80;
    switch(config.server.method) {
        case 'tcp':
            port = config.channels.tcp.port;
            break;
        case 'http2':
            port = config.channels.http2.port;
            break;
        case 'tls':
            port = config.channels.https.port;
            break;
        case 'udp':
            port = config.channels.udp.port;
            break;
        default:
    }
    return port;
}

/**
 * TODO: finish implementation of rate limiting
 * Implement rate limiting per IP
 * @param {string} ipAddress 
 * @param {*} rateLimits 
 * @returns 
 */
const rateLimit = (ipAddress, rateLimits) => {
    const now = Date.now();
    if (!rateLimits[ipAddress]) {
        rateLimits[ipAddress] = { count: 1, lastRequest: now };
        return true;
    }

    const timeSinceLastRequest = now - rateLimits[ipAddress].lastRequest;
    if (timeSinceLastRequest < config.rateLimit.window) {
        if (rateLimits[ipAddress].count >= config.rateLimit.maxRequests) {
            return false;
        }
        rateLimits[ipAddress].count++;
    } else {
        rateLimits[ipAddress] = { count: 1, lastRequest: now };
    }
    return true;
};

/**
 * Get the server local IP address
 * @returns {string}
 */
const getLocalIpAddress = () => {
    try {
        const interfaces = networkInterfaces();
        let localIp;

        // Iterate through the network interfaces
        Object.keys(interfaces).forEach((ifaceName) => {
            interfaces[ifaceName].forEach((iface) => {
                // Skip over non-IPv4 and internal interfaces, and addresses starting with 172. and 127.
                if (iface.family === 'IPv4' && !iface.internal && !iface.address.startsWith('172.') && !iface.address.startsWith('127.')) {
                    localIp = iface.address
                }
            });
        });
        return localIp || 'localhost';
    } catch (error) {
        logError(`Exception: ${error.message}`);
    }
};

module.exports = {
    rateLimit,
    getLocalIpAddress,
    getServerPort
}