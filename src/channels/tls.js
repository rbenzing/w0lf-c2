const tls = require('node:tls');

const startTLSServer = (activeClients, config) => {
    server = tls.createServer({
        key: fs.readFileSync(path.join(__dirname, config.channels.tls.cert.key)),
        cert: fs.readFileSync(path.join(__dirname, config.channels.tls.cert.cert)),
        ciphers: config.channels.tls.ciphers,
        honorCipherOrder: true,
        minVersion: config.channels.tls.version, // Minimum TLS version
        secureOptions: tls.constants.SSL_OP_NO_SSLv2 | tls.constants.SSL_OP_NO_SSLv3 | tls.constants.SSL_OP_NO_COMPRESSION, // Disable SSLv2, SSLv3, and compression
    }, (socket) => {
        // finish
        socket.on('end', () => {
            logInfo(`\nClient ${sessionId} disconnected. IP: ${client.address}`, logStream);
            if (client) {
                client.lastSeen = new Date();
                client.active = false;
            }
        });
        socket.on('error', (err) => {
            logError(`\nClient ${client.sessionId} threw an error: ${err.message}. IP: ${client.address}`, logStream);
            if (client) {
                client.active = false;
            }
        });
    });
};

module.exports = {
    startTLSServer
};