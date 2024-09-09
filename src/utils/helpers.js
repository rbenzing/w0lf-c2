
const { networkInterfaces } = require("node:os");

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

/**
 * Format the uptime to hours, minutes and seconds
 * @param {*} milliseconds 
 * @returns 
 */
const formatTime = (milliseconds) => {
    const totalSeconds = Math.floor(milliseconds / 1000);
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    return `${days}d ${hours}h ${minutes}m ${seconds}s`;
};

/**
 * Get the server uptime
 * @returns 
 */
const getUptime = (startTime) => {
    const currentTime = Date.now();
    const uptimeMillis = currentTime - startTime;
    return `Uptime: ${formatTime(uptimeMillis)}`;
};

module.exports = {
    formatTime,
    getUptime,
    getLocalIpAddress
};