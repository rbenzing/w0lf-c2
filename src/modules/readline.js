const { createInterface } = require('node:readline');
const { logError, log, logSuccess, logInfo }  = require('./logging');

require('../typedef/definitions');

// App readline interface
const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: "\x1b[33mEnter command > \x1b[0m"
});

/**
 * Creates the client console interface using readline
 * @param {Client} client
 * @returns Interface
 */
const createClientConsole = (client) => {
    try {
        const clientRl = createInterface({
            input: client.socket.stdin,
            output: client.socket.stdout,
            prompt: `\x1b[33m${client.address} > \x1b[0m`
        });
        return clientRl;
    } catch (error) {
        logError(`Exception: ${error.message}`);
    }
};

/**
 * Runs the prompt for Readline
 */
const prompt = () => {
    if (rl) {
        rl.prompt();
    }
};

/**
 * Processes and shows the input on the console
 */
const listenServerConsole = () => {
    try {
        rl.on('line', async (input) => {
            try {
                const [command, ...args] = input.trim()
                    .split(/ +(?=(?:(?:[^"]*"){2})*[^"]*$)/); // Use regex to split by any whitespace
                if (!command) {
                    prompt();
                    return;
                }
                log(`Enter command > ${command}\n`, null, true);

                if (command === 'exit') {
                    const { closeServer } = require('./server');
                    logInfo('Server is shutting down...');
                    closeServer();
                    process.exit(0);
                }

                // handle the command
                const { handleCommandWithArgs } = require('./handlers');
                await handleCommandWithArgs(command, args, rl);
                prompt();
            } catch (error) {
                logError(`Error: ${error.message}`);
                prompt();
            }
        });
    } catch (error) {
        logError(`Exception: ${error.message}`);
    }
};

/**
 * Closes the readline instance
 */
const endReadline = () => {
    if (rl) {
        rl.close();
        logSuccess(`Console has been closed.`);
    }
};

/**
 * Clears the server console
 */
const clearServerConsole = () => {
    //console.clear();
    rl.write("\u001b[0J\u001b[1J\u001b[2J\u001b[0;0H\u001b[0;0W", { ctrl: true, name: 'l'});
};

/**
 * Gets the Readline instance
 * @returns Interface
 */
const getReadlineInstance = () => {
    return rl;
};

module.exports = {
    prompt,
    listenServerConsole,
    createClientConsole,
    clearServerConsole,
    endReadline,
    getReadlineInstance
};