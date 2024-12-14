const { logInfo, createLogStream, endLogStream } = require('./logging');
const { getHowel, getStartup } = require('./helpers');
const { loadAndRegisterPlugins } = require('./plugins');
const { clearActiveSession, endClientSessions } = require('./clients');
const { closeSocketServer } = require('../channels/socket');
const { prompt, listenServerConsole } = require('./readline');

const config = require('./config');

/**
 * Starts the server
 */
const startServer = async () => {
    // create log
    await createLogStream();

    // startup logo and info
    getHowel();
    getStartup();

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
    startServer
};