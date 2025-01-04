const { createServer } = require('node:net');
const { logInfo, logError } = require('../modules/logging');
const config = require('../modules/config');

const {
    getSessionId,
    decryptData
} = require('../modules/encdec');
const {
    addClientSession,
    upsertClientSession,
    getClient
} = require('../modules/clients');
const {
    executeQueuedCommands
} = require('../modules/queue');
const {
    handleDownloadResponse,
    handleResponse,
    handleBeacon
} = require('../modules/handlers');

// Create the TCP server
const server = createServer((socket) => {
    const clientAddress = socket.remoteAddress || '1';
    const sessionId = getSessionId(clientAddress);

    // Add client session
    addClientSession(sessionId, socket);

    let clientBuffer = '';

    socket.on('data', async (chunk) => {
        try {
            const payloadStr = chunk.toString('utf8');
            let client = getClient(sessionId);

            if (payloadStr.length >= config.data.chunk_size || payloadStr.includes('--FIN--')) {
                // Chunk mode
                clientBuffer += payloadStr;
                if (clientBuffer.includes('--FIN--')) {
                    const bufferChunks = clientBuffer.replace('--FIN--', '');
                    clientBuffer = '';

                    const decrypted = await decryptData(bufferChunks, client.sessionId);
                    const parsed = JSON.parse(decrypted);
                    const response = parsed.response;

                    if (response.download) {
                        await handleDownloadResponse(response);
                    } else {
                        await handleResponse(response);
                    }

                    upsertClientSession(sessionId, { waiting: false, buffer: '' });
                } else {
                    upsertClientSession(sessionId, { waiting: true, buffer: clientBuffer });
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
            logError(`Error processing data from client ${sessionId}: ${err.message}`);
        }
    });

    socket.on('end', () => {
        const client = getClient(sessionId);
        logInfo(`Client ${sessionId} disconnected. IP: ${client.address}`);
        upsertClientSession(sessionId, { lastSeen: new Date(), active: false });
    });

    socket.on('error', (err) => {
        const client = getClient(sessionId);
        logError(`Client ${sessionId} threw an error: ${err.message}. IP: ${client.address}`);
        upsertClientSession(sessionId, { active: false });
    });

    socket.setKeepAlive(true); // Enable keep-alive to improve connection stability
});

/**
 * Starts listening on the server
 */
const listenSocketServer = () => {
    server.listen(config.channels.tcp.port, config.server.host);

    server.on('error', (err) => {
        logError(`Server error: ${err.message}`);
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
 * Closes the server connection
 */
const closeSocketServer = async () => {
    if (server) {
        server.close(() => {
            logInfo('Server connection closed');
            server.unref();
        });
    }
};

module.exports = {
    closeSocketServer,
    getServerInstance,
    listenSocketServer
};
