const { networkInterfaces } = require("node:os");

/**
 * Implement rate limiting per IP
 * @param {*} ipAddress 
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
 * @returns 
 */
const getLocalIpAddress = () => {
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
};

module.exports = {
    rateLimit,
    getLocalIpAddress
}