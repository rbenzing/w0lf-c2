
const { mkdir, existsSync, createWriteStream } = require('node:fs');
const { join } = require('node:path');
const { promisify } = require('node:util');

const mkdir_promise = promisify(mkdir);
const config = require('./config');

let logStream = null; // log stream instance
let currentLineCount = 0; // current log line count
let logFileIndex = 1; // log file index

const LOGS_FOLDER = join(__dirname, "../", config.path.logs);

/**
 * Create a writable stream for logging
 */
const createLogStream = async () => {
    if (config.logging.enable) {
        if (!existsSync(LOGS_FOLDER)) {
            await mkdir_promise(LOGS_FOLDER);
        }
        const logFilePath = join(LOGS_FOLDER, `${config.logging.filename}_${logFileIndex}.log`);
        logStream = createWriteStream(logFilePath, { flags: 'a' });
    }
};

/**
 * Basic log to console and/or file
 * @param {string|string[]} texts 
 * @param {string|string[]} colors 
 * @param {boolean} skipConsole 
 * @returns 
 */
const log = async (texts, colors = 97, skipConsole = false) => {
    if (config.logging.enable) {
        // Ensure texts and colors are arrays
        texts = Array.isArray(texts) ? texts : [texts];
        colors = Array.isArray(colors) ? colors : [colors];

        // Check that the lengths of texts and colors match
        if (texts.length !== colors.length) {
            console.error("Error: The lengths of texts and colors should match.");
            return;
        }

        if (config.logging.fileLogging && logStream) {
            const message = texts.join(' ');
            const lineCount = message.split(/\r\n|\r|\n/).length;
            currentLineCount += lineCount;
            if (currentLineCount >= config.logging.maxlines) {
                logStream.end();
                logFileIndex++;
                logStream = await createLogStream(logFileIndex);
                currentLineCount = 0;
            }
            logStream.write(`${message}\n`);
        }
        if (!skipConsole) {
            // Format and log to console
            const formattedText = texts.map((text, index) => `\x1b[${colors[index]}m${text}\x1b[0m`).join(' ');
            console.log(formattedText);
        }
    }
};

/**
 * Close the logstream
 */
const endLogStream = () => {
    if (logStream) {
        // stop log stream
        logStream.end();
        logStream = null; // log stream instance
        logSuccess(`LogStream has been closed.`);
    }
};

/**
 * Log an error message
 * @param {string} error 
 */
const logError = (error) => {
    log(error, 91); // Bright Red
};

/**
 * Log an info message
 * @param {string} info 
 */
const logInfo = (info) => {
    log(info, 37); // White
};

/**
 * Log a success message
 * @param {string} success 
 */
const logSuccess = (success) => {
    log(success, 92); // Bright Green
};

module.exports = {
    createLogStream,
    endLogStream,
    log,
    logError,
    logInfo,
    logSuccess,
};