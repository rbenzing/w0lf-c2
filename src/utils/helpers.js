
const { networkInterfaces } = require("node:os");
const { log } = require('./logging');
const config = require('../config/configLoader');

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
const getUptime = (startTime) => {
    const currentTime = Date.now();
    const uptimeMillis = currentTime - startTime;
    return `Uptime: ${formatTime(uptimeMillis)}`;
};

/**
 * Get the w0lf c2 startup ascii
 */
const getHowel = (logStream) => {
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

/**
 * Get the w0lf c2 startup text
 */
const getWolfText = (logStream) => {
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
const getStartup = (startTime, logStream) => {
    getWolfText(logStream);
    log([`Ver. ${config.version}`, ' | ',`Listening on: ${getLocalIpAddress()}:${config.server.port}`, ' | ', `${getUptime(startTime)}`], [94, 97, 93, 97, 93], logStream);
};

/**
 * Displays the active plugins
 */
const displayActivePlugins = (loadedPlugins, logStream) => {
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
const displayCommandOptions = (loadedPlugins, logStream) => {
    log("\nSERVER COMMANDS:", 93, logStream);
    log(["help\t\t", "Display available commands."], [96, 97], logStream);
    log(["plugins \t", "List all active plugins."], [96, 97], logStream);
    log(["clients \t", "List all active clients."], [96, 97], logStream);
    log(["uptime\t\t", "Display server uptime."], [96, 97], logStream);
    log(["set\t\t", "Sets the client session to make active."], [96, 97], logStream);
    log(["clear\t\t", "Clear the console."], [96, 97], logStream);
    log(["exit\t\t", "Exit the server."], [96, 97], logStream);
    if (loadedPlugins.length > 0) {
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
    }
};

module.exports = {
    formatTime,
    getUptime,
    getLocalIpAddress,
    displayCommandOptions,
    displayActivePlugins,
    getWolfText,
    getHowel,
    getStartup
};