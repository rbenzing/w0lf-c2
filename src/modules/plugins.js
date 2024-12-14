const { readdir } = require('node:fs');
const { join } = require('node:path');
const { promisify } = require('node:util');
const { logInfo, logError } = require('./logging');
const { addServerCommands, addClientCommands } = require('./commands');

const readdir_promise = promisify(readdir);
const config = require('./config');

const loadedPlugins = new Map();

/**
 * Loads and registers plugins for the server
 * @param {*} logStream 
 */
const loadAndRegisterPlugins = async () => {
    try {
        const pluginFiles = await readdir_promise(join(`${__dirname}/../`, config.path.plugins), { withFileTypes: true });
        await Promise.all(pluginFiles.map((file) => {
            const pluginName = file.name;
            const pluginModule = require(`${__dirname}/../${config.path.plugins}/${pluginName}`);
            
            if (!pluginModule || typeof pluginModule !== 'object') {
                logError(`Invalid plugin module in file "${pluginName}". Skipping...`);
                return;
            }
            // Check if the plugin module exports the 'commands' object
            if (!pluginModule.commands) {
                logError(`Plugin "${pluginName}" does not have valid commands defined.`);
                return;
            }
            if (file.isFile()) {
                let plugin = registerPlugin({ name: pluginName, module: pluginModule });
                // Add the plugin to the loaded plugins map
                loadedPlugins.set(plugin.name, plugin.module);
            }
        }));
    } catch (err) {
        logError(`Error loading plugins: ${err.message}`);
    }
};

/**
 * Registers a plugin in the server config
 * @param {*} plugin
 */
const registerPlugin = (plugin) => {
    // Register additional commands provided by the plugin
    if (plugin && plugin.module) {
        const commandKeys = Object.keys(plugin.module.commands).filter(c => c.method !== 'execute');
        
        if (plugin.module.type === 'server') {
            addServerCommands(commandKeys);
        } else if(plugin.module.type === 'client') {
            addClientCommands(commandKeys);
        }
        commandKeys.forEach((command) => {
            // Extract command name and function
            const cmd = plugin.module.commands[command],
                  name = cmd.name,
                  handler = cmd.handler;

            // Check if the command name is not already registered
            if (!global[name]) {
                // Register the command globally
                global[name] = handler;
            } else {
                logError(`Plugin: "${plugin.name}" is already registered.`);
            }
        });
    }
    logInfo(`Plugin: "${plugin.name} - ${plugin.module.description}" has been registered.`);
    return plugin;
};

/**
 * Returns the loaded plugins
 * @returns Map<any, any>
 */
const getLoadedPlugins = () => {
    return loadedPlugins;
};

module.exports = {
    getLoadedPlugins,
    loadAndRegisterPlugins
};