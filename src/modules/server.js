const { logInfo, createLogStream, endLogStream } = require('./logging');
const { getHowel, getStartup } = require('./helpers');
const { loadAndRegisterPlugins } = require('./plugins');
const { clearActiveSession, endClientSessions } = require('./clients');
const { closeSocketServer } = require('../channels/socket');
const { prompt, listenServerConsole } = require('./readline');

const config = require('./config');

const startTime = Date.now();

/**
 * Starts the server
 */
const startServer = async () => {
    // create log
    await createLogStream();

    // Load Channel
    switch (config.server.method) {
        case "tcp":
            const { listenSocketServer } = require('../channels/socket');
            listenSocketServer();
            break;
        case "tls":
            const { startTLSServer } = require('../channels/tls');
            startTLSServer();
            break;
        case "http2":
            const { startHTTP2Server } = require('../channels/http2');
            startHTTP2Server();
            break;
        case "udp":
            const { startUDPServer } = require('../channels/udp');
            startUDPServer();
            break;
        default:
            shutdown();
    }

    // startup logo and info
    getHowel();
    getStartup(startTime);

    // register plugins
    await loadAndRegisterPlugins();

    // create server console
    listenServerConsole()

    // prompt
    prompt();
};

/**
 * Closes the server connection
 */
const closeServer = () => {
    // ends all client sessions
    endClientSessions(); 
    // clears the active session
    clearActiveSession();
    // close server connection
    switch (config.server.method) {
        case "tcp":
            closeSocketServer();
            break;
        case "tls":
            break;
        case "http2":
            break;
        case "udp":
            break;
        default:
    }
    // ends the logstream
    endLogStream();
};

/**
 * Shutdown the server on SIGTERM/SIGINT
 */
const shutdown = () => {
    logInfo('Server is shutting down...');
    closeServer();
    process.exit(0);
};

module.exports = {
    closeServer,
    shutdown,
    startServer,
    startTime
};