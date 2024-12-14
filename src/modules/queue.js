const { logInfo }  = require('./logging');

require('../typedef/definitions');

const queuedCommands = new Map();

/**
 * Execute the queued command on a client
 * @param {Client} client
 */
const executeQueuedCommands = async (client) => {
    if (!client || !client.sessionId) {
        throw new Error('No active session ID set.');
    }
    const commands = queuedCommands.get(client.sessionId);
    if (commands) {
        commands.forEach(async ({ command, args }) => {
            await executeClientCommand(client, [command, ...args].join(' '));
            logInfo(`Queued client command executed: ${command} ${args.join(' ')}`);
        });
        queuedCommands.delete(client.sessionId);
    }
};

/**
 * Adds a command to the queue for a client
 * @param {Client} client 
 * @param {string} command 
 * @param {string[]} args
 */
const queueCommands = async (client, command, args) => {
    await new Promise((resolve) => {
        const queuedCommandsForSession = queuedCommands.get(client.sessionId) || [];
        queuedCommandsForSession.push({ command, args });
        logInfo(`Queued command for client ${client.sessionId}. Command: ${command} ${args.join(' ')}`);
        queuedCommands.set(client.sessionId, queuedCommandsForSession);
        resolve(true);
    });
};

/**
 * Returns the queued commands
 * @returns {Map<any, any>}
 */
const getQueuedCommands = () => {
    return queuedCommands;
};

module.exports = {
    executeQueuedCommands,
    getQueuedCommands,
    queueCommands
};