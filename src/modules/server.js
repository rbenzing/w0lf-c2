const { logInfo, createLogStream, endLogStream } = require('./logging');
const { getHowel, getStartup } = require('./helpers');
const { loadAndRegisterPlugins } = require('./plugins');
const { clearActiveSession, endClientSessions } = require('./clients');
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
            const { listenTLSServer } = require('../channels/tls');
            listenTLSServer();
            break;
        case "http2":
            const { listenHTTP2Server } = require('../channels/http2');
            listenHTTP2Server();
            break;
        case "udp":
            const { listenUDPServer } = require('../channels/udp');
            listenUDPServer();
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
            const { closeSocketServer } = require('../channels/socket');
            closeSocketServer();
            break;
        case "tls":
            const { closeTLSServer } = require('../channels/tls');
            closeTLSServer();
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