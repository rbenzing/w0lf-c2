const { getHowel } = require('./helpers');
const { log, logInfo, logSuccess, logError } = require('./logging');

/**
 * Sets the active client session ID
 * @param {*} activeClientSessionID 
 * @param {*} sessionId 
 * @param {*} logStream 
 * @returns 
 */
const setClientActive = (activeClientSessionID, sessionId, logStream) => {
    if (!sessionId) {
        activeClientSessionID = null;
        log('The active session ID has been cleared.', undefined, logStream);
        return;
    }
    let clientExists = activeClients.get(sessionId);
    if (sessionId && clientExists && sessionId.length === 32) {
        activeClientSessionID = sessionId;
        log(`${activeClientSessionID} is now the active session.`, undefined, logStream);
    } else {
        logError('Invalid session ID.', logStream);
    }
    return activeClientSessionID;
};

/**
 * Shows the full active client details
 * @param {*} activeClientSessionID 
 * @param {*} activeClients 
 * @param {*} logStream 
 */
const showClient = (activeClientSessionID, activeClients, logStream) => {
    if (!activeClientSessionID) {
        throw new Error(`You must set a session ID first.`);
    }
    const client = activeClients.get(activeClientSessionID);
    if (!client) {
        throw new Error(`Invalid session ID: ${activeClientSessionID}`);
    }
    log("\nClient Details:", 93, logStream);
    log(["Last Seen:\t\t", client.lastSeen], [96, 97], logStream);
    log(["Active:\t\t\t", client.active], [96, 97], logStream);
    log(["Session ID:\t\t", client.sessionId], [96, 97], logStream);
    log(["Hostname:\t\t", client.hostname], [96, 97], logStream);
    log(["IP Address:\t\t", client.address], [96, 97], logStream);
    log(["Type:\t\t\t", client.type], [96, 97], logStream);
    log(["Client Ver:\t\t", client.version], [96, 97], logStream);
    log(["Architecture:\t\t", client.arch], [96, 97], logStream);
    log(["Platform:\t\t", client.platform], [96, 97], logStream);
    log(["OS Ver:\t\t\t", client.osver, "\n"], [96, 97, 97], logStream);
};

/**
 * Shows the clients list
 * @param {*} activeClients 
 * @param {*} logStream 
 * @returns 
 */
const showActiveClients = (activeClients, logStream) => {
    if (activeClients.size === 0) {
        getHowel(logStream);
        logInfo('No active clients.', logStream);
        return;
    }
    const active = Array.from(activeClients.values()).filter(client => client.active).length;
    logSuccess(`\nClient Sessions (${activeClients.size} Total / ${active} Active):`, logStream);
    const colWidths = [36, 15, 20, 10, 10, 10, 10];
    const totalWidth = colWidths.reduce((sum, width) => sum + width, 0) + colWidths.length + 1;
    const pad = (str, len) => str ? str.padEnd(len) : "".padEnd(10);
    logInfo('┌' + '─'.repeat(totalWidth - 2) + '┐', logStream);
    logInfo('│' + pad('SessionID', colWidths[0]) + '│' +
                     pad('ClientIP', colWidths[1]) + '│' +
                     pad('Updated', colWidths[2]) + '│' +
                     pad('Online', colWidths[3]) + '│' +
                     pad('Active', colWidths[4]) + '│' +
                     pad('Ver', colWidths[5]) + '│' +
                     pad('Type', colWidths[6]) + '│', logStream);
    logInfo('├' + colWidths.map(w => '─'.repeat(w)).join('┼') + '┤', logStream);
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
                         pad(client.sessionId === activeClientSessionID ? 'Yes' : 'No', colWidths[4]) + '│' +
                         pad(client.version, colWidths[5]) + '│' +
                         pad(client.type, colWidths[6]) + '│', logStream);
    }
    logInfo('└' + colWidths.map(w => '─'.repeat(w)).join('┴') + '┘', logStream);
};

/**
 * Execute the queued command on a client
 * @param {*} client 
 * @param {*} queuedCommands 
 * @param {*} logStream 
 */
const executeQueuedCommands = async (client, queuedCommands, logStream) => {
    if (!client || !client.sessionId) {
        throw new Error('No active session ID set.');
    }
    const commands = queuedCommands.get(client.sessionId);
    if (commands) {
        commands.forEach(async ({ command, args }) => {
            await executeClientCommand(client, `${command} ${args.join(' ')}`);
            logInfo(`Queued client command executed: ${command} ${args.join(' ')}`, logStream);
        });
        queuedCommands.delete(client.sessionId);
    }
};

module.exports = {
    showClient,
    setClientActive,
    showActiveClients,
    executeQueuedCommands
};