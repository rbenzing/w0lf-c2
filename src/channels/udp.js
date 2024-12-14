const dgram = require('dgram');
const { getSessionId } = require('../modules/encdec');

const startUDPServer = (activeClients, config) => {
    const controller = new AbortController();
    const { signal } = controller;

    let chunkSize = config.data.chunk_size + 1;
    const server = dgram.createSocket({
        type: config.channels.udp.type,
        recvBufferSize: chunkSize,
        sendBufferSize: chunkSize,
        signal
    });

    // Handle incoming messages
    server.on('message', (msg, rinfo) => {
        const sessionId = getSessionId(ipAddress)
        let client = activeClients.get(sessionId);
        if (!client) {
            client = {
                sessionId: sessionId,
                socket: socket,
                address: ipAddress,
                lastSeen: new Date(),
                active: true,
                buffer: '',
                waiting: false,
                version: null,
                type: null,
                platform: null, 
                arch: null, 
                osver: null, 
                hostname: null
            };
            activeClients.set(sessionId, client);
        } else {
            client.active = true;
            client.socket = socket;
            client.lastSeen = (new Date()).getDate();
        }

        console.log(`Received message from ${client.sessionId}: ${msg}`);

        // Echo the message back to the client
        server.send(msg, rinfo.port, rinfo.address, (err) => {
            if (err) {
                console.error(`Error sending message to ${client}: ${err.message}`);
            } else {
                console.log(`Message sent back to ${client}`);
            }
        });
    });

    server.on('listening', () => {
        const address = server.address();
        console.log(`Server listening on ${address.address}:${address.port}`);
    });
};

module.exports = {
    startUDPServer
};