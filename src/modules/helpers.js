
const { log } = require('./logging');
const { getServerPort } = require('./network');
const { getLoadedPlugins } = require('./plugins');

const config = require('./config');

var startTime = null;

/**
 * Returns the formatted uptime in hours, minutes and seconds
 * @param {number} milliseconds 
 * @returns {string}
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
 * Returns the server uptime
 * @param {string} startTime 
 * @returns {string}
 */
const getUptime = (startTime) => {
    const currentTime = Date.now();
    const uptimeMillis = currentTime - startTime;
    return formatTime(uptimeMillis);
};

/**
 * Get the w0lf c2 startup ascii
 */
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
⠀⠀⠀⢠⠟⣹⣧⠃⠀⠀⢿⢻⡀⢄⠀⠀⠀⠀⠐⣦⡀⣸⣆⠀⣾⣧⣯⢻`, undefined);
};

/**
 * Get the w0lf c2 startup text
 */
const getWolfText = () => {
    log(`██╗⠘⣰⣿⣿██╗ ██████╗ ██╗⢶⣿⡎⠻⣆███████╗     ██████╗██████╗ 
██║⡟⡿⢿⡿██║██╔═████╗██║⠙⢿⡄⡈⢆██╔════╝    ██╔════╝╚════██╗
██║ █╗ ██║██║██╔██║██║⠀⡇⢹⢿⡀█████╗      ██║      █████╔╝
██║███╗██║████╔╝██║██║⠀⠀⠼⠇⠁██╔══╝      ██║     ██╔═══╝ 
╚███╔███╔╝╚██████╔╝███████╗██║         ╚██████╗███████╗
 ╚══╝╚══╝  ╚═════╝ ╚══════╝╚═╝          ╚═════╝╚══════╝`, undefined);
};

/**
 * Shows the startup info
 */
const getStartup = () => {
    getWolfText();
    startTime = Date.now();
    log([`Ver. ${config.version}`, ' | ',`Listening on: ${config.server.host}:${getServerPort()}`, ' | ', `Uptime: ${getUptime(startTime)}`], [94, 97, 93, 97, 93]);
};

/**
 * Displays the active plugins
 */
const displayActivePlugins = () => {
    const loadedPlugins = getLoadedPlugins();
    log("\nACTIVE PLUGINS:", 93);
    Array.from(loadedPlugins).forEach(plugin => {
        const [ name, module ] = plugin;
        log(["Type:", `\t\t${module.type} plugin`], [96, 97]);
        log(["Name:", `\t\t${name}`], [96, 97]);
        log(["Description:", `\t${module.description}`], [96, 97]);
        log(["Commands:", `\t${Object.keys(module.commands).join(', ')}\n`], [96, 97]);
    });
};

/**
 * Displays the server commands
 */
const displayCommandOptions = () => {
    const loadedPlugins = getLoadedPlugins();
    log("\nSERVER COMMANDS:", 93);
    log(["help\t\t", "Display available commands."], [96, 97]);
    log(["plugins \t", "List all active plugins."], [96, 97]);
    log(["clients \t", "List all active clients."], [96, 97]);
    log(["uptime\t\t", "Display server uptime."], [96, 97]);
    log(["set\t\t", "Sets the client session to make active."], [96, 97]);
    log(["clear\t\t", "Clear the console."], [96, 97]);
    log(["exit\t\t", "Exit the server."], [96, 97]);
    if (loadedPlugins) {
        log("\nPLUGINS:", 93);
        for (const [pluginName, pluginModule] of loadedPlugins.entries()) {
            log(`${pluginName}: ${pluginModule.description}`, 93);
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
                    log([`${command}${format}`, `${pluginModule.commands[command].description}${format2}`], [96, 97]);
                });
            }
        }
    }
};

module.exports = {
    formatTime,
    getUptime,
    displayCommandOptions,
    displayActivePlugins,
    getWolfText,
    getHowel,
    getStartup
};