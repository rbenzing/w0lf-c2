const { logInfo, logError }  = require('./logging');

require('../typedef/definitions');

const queuedCommands = new Map();

/**
 * Execute the queued command on a client
 * @param {Client} client
 */
const executeQueuedCommands = async (client) => {
    try {
        if (!client || !client.sessionId) {
            throw new Error('No active session ID set.');
        }
        const commands = queuedCommands.get(client.sessionId);
        if (commands) {
            commands.forEach(async ({ command, args }) => {
                const { executeClientCommand } = require('./clients');
                await executeClientCommand(client, [command, ...args].join(' '));
                logInfo(`Queued client command executed: ${command} ${args.join(' ')}`);
            });
            queuedCommands.delete(client.sessionId);
        }
    } catch (error) {
        logError(`Exception: ${error.message}`);
    }
};

/**
 * Adds a command to the queue for a client
 * @param {Client} client 
 * @param {string} command 
 * @param {string[]} args
 */
const queueCommands = async (client, command, args) => {
    try {
        await new Promise((resolve) => {
            const queuedCommandsForSession = queuedCommands.get(client.sessionId) || [];
            queuedCommandsForSession.push({ command, args });
            logInfo(`Queued command for client ${client.sessionId}. Command: ${command} ${args.join(' ')}`);
            queuedCommands.set(client.sessionId, queuedCommandsForSession);
            resolve(true);
        });
    } catch (error) {
        logError(`Exception: ${error.message}`);
    }
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