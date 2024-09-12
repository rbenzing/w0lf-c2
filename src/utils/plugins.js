const { readdir } = require('node:fs');
const { join } = require('node:path');
const { promisify } = require('node:util');
const { logInfo, logError } = require('./logging');
const readdir_promise = promisify(readdir);
const config = require('../config/configLoader');

/**
 * Loads plugins for the server then registers them
 * @param {*} clientCommands 
 * @param {*} serverCommands 
 * @param {*} loadedPlugins 
 * @param {*} logStream 
 */
const loadAndRegisterPlugins = async (clientCommands, serverCommands, loadedPlugins, logStream) => {
    try {
        const pluginFiles = await readdir_promise(join(`${__dirname}/../`, config.path.plugins), { withFileTypes: true });
        await Promise.all(pluginFiles.map((file) => {
            const pluginName = file.name;
            const pluginPath = join(`${__dirname}/../${config.path.plugins}`, pluginName);
            const pluginModule = require(pluginPath);
            if (!pluginModule || typeof pluginModule !== 'object') {
                logError(`Invalid plugin module in file "${pluginName}". Skipping...`, logStream);
                return;
            }
            // Check if the plugin module exports the 'commands' object
            if (!pluginModule.commands) {
                logError(`Plugin "${pluginName}" does not have valid commands defined.`, logStream);
                return;
            }
            if (file.isFile()) {
                let plugin = registerPlugin({ name: pluginName, module: pluginModule }, clientCommands, serverCommands, logStream);
                // Add the plugin to the loaded plugins map
                loadedPlugins.set(plugin.name, plugin.module);
            }
        }));
    } catch (err) {
        logError(`Error loading plugins: ${err.message}`, logStream);
    }
};

/**
 * Registers a plugin for the server
 * @param {*} plugin 
 * @param {*} clientCommands
 * @param {*} logStream 
 */
const registerPlugin = (plugin, clientCommands, serverCommands, logStream) => {
    // Register additional commands provided by the plugin
    if (plugin && plugin.module) {
        const commandKeys = Object.keys(plugin.module.commands).filter(c => c.method !== 'execute');
        if (plugin.module.type === 'server') {
            serverCommands.push(...commandKeys);
        } else if(plugin.module.type === 'client') {
            clientCommands.push(...commandKeys);
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
                logError(`Plugin: "${plugin.name}" is already registered.`, logStream);
            }
        });
    }
    logInfo(`Plugin: "${plugin.name} - ${plugin.module.description}" has been registered.`, logStream);
    return plugin;
};

module.exports = {
    loadAndRegisterPlugins
};