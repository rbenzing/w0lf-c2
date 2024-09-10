
const { mkdir, existsSync, createWriteStream } = require('node:fs');
const { join } = require('node:path');
const { promisify } = require('node:util');

const config = require('../config/configLoader');

const mkdir_promise = promisify(mkdir);

let currentLineCount = 0; // current log line count
let logFileIndex = 1; // log file index
let _scope_config = null; // scoped config object

const LOGS_FOLDER = join("../", config.path.logs);

// Create a writable stream for logging
const createLogStream = async () => {
    _scope_config = config;
    if (config.logging.enabled) {
        if (!existsSync(LOGS_FOLDER)) {
            await mkdir_promise(LOGS_FOLDER);
        }
        const filename = config.logging.filename.split('.')[0];
        const logFilePath = join(LOGS_FOLDER, `${filename}_${logFileIndex}.log`);
        return createWriteStream(logFilePath, { flags: 'a' });
    }
    return null;
};

const log = async (texts, colors = 97, logStream) => {
    // Ensure texts and colors are arrays
    texts = Array.isArray(texts) ? texts : [texts];
    colors = Array.isArray(colors) ? colors : [colors];

    // Check that the lengths of texts and colors match
    if (texts.length !== colors.length) {
        console.error("Error: The lengths of texts and colors should match.");
        return;
    }

    if (_scope_config.logging.enabled && logStream) {
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

    // Format and log to console
    const formattedText = texts.map((text, index) => `\x1b[${colors[index]}m${text}\x1b[0m`).join(' ');
    console.log(formattedText);
};

const logError = (error, logStream) => {
    log(error, 91, logStream); // Bright Red
};
const logInfo = (info, logStream) => {
    log(info, 37, logStream); // White
};
const logSuccess = (success, logStream) => {
    log(success, 92, logStream); // Bright Green
};

module.exports = {
    createLogStream,
    log,
    logError,
    logInfo,
    logSuccess,
};