
const serverCommands = ['help', 'client', 'clients', 'exit', 'plugins', 'set', 'uptime', 'clear'];
const clientCommands = [];

/**
 * Returns the client commands
 * @returns string[]
 */
const getClientCommands = () => {
    return clientCommands;
};

/**
 * Returns the server commands
 * @returns string[]
 */
const getServerCommands = () => {
    return serverCommands;
};

/**
 * Add command to the client commands
 */
const addClientCommands = (commands) => {
    commands.forEach(command => {
        clientCommands.push(command);
    });
};

/**
 * Add command to the server commands
 */
const addServerCommands = (commands) => {
    commands.forEach(command => {
        serverCommands.push(command);
    }); 
};

module.exports = {
    addClientCommands,
    addServerCommands,
    getClientCommands,
    getServerCommands
};