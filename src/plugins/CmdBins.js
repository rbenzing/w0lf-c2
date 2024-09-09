// Register a plugin
module.exports = {
    name: 'Cmd.exe Binaries',
    type: 'client',
    description: 'A client plugin that provides native cmd.exe commands.',
    commands: {
        reg: {
            name: 'reg',
            method: 'payload-cmd',
            description: `Send command reg.exe to manage the windows registry.`,
            parameters: {
                'query': 'Query a registry key.',
                'add': 'Add a new registry entry.',
                'delete': 'Delete a registry entry.',
                'export': 'Export a registry key to a file.',
                'import': 'Import registry data from a file.',
                'copy': 'Copy a registry key to another location.',
                'unload': 'Unload a registry hive.',
                'compare': 'Compare two registry keys.'
            },
            handler: (props) => {
                const commands = {
                    query: {
                        params: ['key'],
                        format: (props) => `query "${props[0]}" /s`
                    },
                    add: {
                        params: ['key', 'valueName', 'valueData'],
                        format: (props) => `add "${props[0]}" /v "${props[1]}" /d "${props[2]}"`
                    },
                    delete: {
                        params: ['key', 'valueName'],
                        format: (props) => `delete "${props[0]}" /v "${props[1]}" /f`
                    },
                    export: {
                        params: ['key', 'outputFile'],
                        format: (props) => `export "${props[0]}" "${props[1]}"`
                    },
                    import: {
                        params: ['inputFile'],
                        format: (props) => `import "${props[0]}"`
                    },
                    copy: {
                        params: ['sourceKey', 'destinationKey'],
                        format: (props) => `copy "${props[0]}" "${props[1]}"`
                    },
                    unload: {
                        params: ['key'],
                        format: (props) => `unload "${props[0]}"`
                    },
                    compare: {
                        params: ['key1', 'key2'],
                        format: (props) => `compare "${props[0]}" "${props[1]}"`
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
            
                const cmd = `reg.exe ${formattedCommand}`;
                return Buffer.from(cmd).toString('base64');
            }
        },
        ipconfig: {
            name: 'ipconfig',
            method: 'payload-cmd',
            description: `Send ipconfig commands.`,
            parameters: {
                'all': 'Shows all interfaces on the client.',
                'release': 'Release the IP address for the specified adapter.',
                'renew': 'Renew the IP address for the specified adapter.',
                'flushdns': 'Flush the DNS resolver cache.',
                'displaydns': 'Display the contents of the DNS resolver cache.',
                'registerdns': 'Refreshes all DHCP leases and re-registers DNS names.',
                'showclassid': 'Displays all the DHCP class IDs allowed for adapter.',
                'setclassid': 'Modifies the DHCP class ID for the specified adapter.',
                'setclassid6': 'Modifies the DHCPv6 class ID for the specified adapter.'
            },
            handler: (props) => {
                const commands = {
                    all: {
                        params: [],
                        format: () => `/all`
                    },
                    release: {
                        params: ['adapter'],
                        format: (props) => `/release ${props[0]}`
                    },
                    renew: {
                        params: ['adapter'],
                        format: (props) => `/renew ${props[0]}`
                    },
                    flushdns: {
                        params: [],
                        format: () => `/flushdns`
                    },
                    registerdns: {
                        params: [],
                        format: () => `/registerdns`
                    },
                    displaydns: {
                        params: [],
                        format: () => `/displaydns`
                    },
                    showclassid: {
                        params: ['adapter'],
                        format: (props) => `/showclassid ${props[0]}`
                    },
                    setclassid: {
                        params: ['adapter', 'id'],
                        format: (props) => `/setclassid ${props[0]} ${props[1]}`
                    },
                    showclassid6: {
                        params: ['adapter'],
                        format: (props) => `/showclassid6 ${props[0]}`
                    },
                    setclassid6: {
                        params: ['adapter', 'id'],
                        format: (props) => `/setclassid6 ${props[0]} ${props[1]}`
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
            
                const cmd = `ipconfig ${formattedCommand}`;
                return Buffer.from(cmd).toString('base64');
            }
        },
        schtasks: {
            name: 'schedule',
            method: 'payload-cmd',
            description: 'Schedule a recurring task.',
            parameters: {
                'create': 'Creates a new scheduled task.',
                'delete': 'Deletes a scheduled task.',
                'run': 'Runs a scheduled task immediately.',
                'end': 'Ends a running scheduled task.',
                'query': 'Displays information about scheduled tasks.',
                'change': 'Changes properties of a scheduled task.',
            },
            handler: (props) => {
                const commands = {
                    create: {
                        params: ['taskName', 'executablePath', 'occurrence', 'time'],
                        format: (props) => `/create /tn "${props[0]}" /tr "${props[1]}" /sc ${props[2] ?? 'daily'} /st ${props[3] ?? '07:00'}`
                    },
                    delete: {
                        params: ['taskName'],
                        format: (props) => `/delete /tn "${props[0]}" /f`
                    },
                    run: {
                        params: ['taskName'],
                        format: (props) => `/run /tn "${props[0]}"`
                    },
                    end: {
                        params: ['taskName'],
                        format: (props) => `/end /tn "${props[0]}"`
                    },
                    query: {
                        params: ['taskName'],
                        format: (props) => `/query /tn "${props[0]}"`
                    },
                    change: {
                        params: ['taskName', 'newExecutablePath', 'occurrence', 'time'],
                        format: (props) => `/change /tn "${props[0]}" /tr "${props[1]}"${props[2] ? ` /sc ${props[2]}` : ''}${props[3] ? ` /st ${props[3]}` : ''}`
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
            
                const cmd = `schtasks ${formattedCommand}`;
                return Buffer.from(cmd).toString('base64');
            }
        },
        systeminfo: {
            name: 'systeminfo',
            method: 'payload-cmd',
            description: 'Returns the system information.',
            parameters: {},
            handler: () => {
                return Buffer.from(`systeminfo`).toString('base64');
            }
        },
        tasklist: {
            name: 'tasklist',
            method: 'payload-cmd',
            description: `Uses tasklist to return the running processes.`,
            parameters: {
                'list': 'Lists all running tasks or specific task by PID with verbose details.',
                'dlls': 'Lists all tasks with loaded DLLs.',
                'services': 'Lists all tasks with associated services.',
                'kill': 'Terminates a task by PID forcefully.',
                'username': 'Lists tasks for a specific username with verbose details.',
                'imagename': 'Lists tasks for a specific image name with verbose details.',
                'status': 'Lists tasks with a specific status with verbose details.',
                'session': 'Lists tasks for a specific session ID with verbose details.',
                'cputime': 'Lists tasks with a specific CPU time with verbose details.',
                'memusage': 'Lists tasks with a specific memory usage with verbose details.'
            },
            handler: (props) => {            
                const commands = {
                    'list': {
                        params: ['pid'],
                        format: (props) => {
                            if (props[0]) {
                                return `tasklist /fi "PID eq ${props[0]}" /v /fo list`;
                            } else {
                                return `tasklist /v /fo table`;
                            }
                        }
                    },
                    'dlls': {
                        params: [],
                        format: () => `tasklist /m /fo table`
                    },
                    'services': {
                        params: [],
                        format: () => `tasklist /svc /fo table`
                    },
                    'kill': {
                        params: ['pid'],
                        format: (props) => `taskkill /PID ${props[0]} /F`
                    },
                    'username': {
                        params: ['username'],
                        format: (props) => `tasklist /fi "USERNAME eq ${props[0]}" /v /fo table`
                    },
                    'imagename': {
                        params: ['imagename'],
                        format: (props) => `tasklist /fi "IMAGENAME eq ${props[0]}" /v /fo table`
                    },
                    'status': {
                        params: ['status'],
                        format: (props) => `tasklist /fi "STATUS eq ${props[0]}" /v /fo table`
                    },
                    'session': {
                        params: ['sessionid'],
                        format: (props) => `tasklist /fi "SESSION eq ${props[0]}" /v /fo table`
                    },
                    'cputime': {
                        params: ['cputime'],
                        format: (props) => `tasklist /fi "CPUTIME eq ${props[0]}" /v /fo table`
                    },
                    'memusage': {
                        params: ['memusage'],
                        format: (props) => `tasklist /fi "MEMUSAGE eq ${props[0]}" /v /fo table`
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
        netsh: {
            name: 'netsh',
            method: 'payload-cmd',
            description: `Uses netsh to return the network info.`,
            parameters: {
                'services': 'Shows the processes related to their services. e.g. ps service',
                'dll': 'Shows the processes related to their dlls. e.g. ps dll',
                'kill': 'Kill a process by ID. e.g. ps kill 3242',
                'list': 'List all or individual processes. e.g. ps list 3242'
            },
            handler: (props) => {
                const contexts = {
                    'interface ip': {
                        commands: {
                            setaddress: {
                                params: ['name', 'source', 'addr', 'mask', 'gateway', 'gwmetric'],
                                format: (props) => `set address name="${props[0]}" source=${props[1]} addr=${props[2]} mask=${props[3]} gateway=${props[4]} gwmetric=${props[5]}`
                            },
                            setdns: {
                                params: ['name', 'source', 'addr', 'register'],
                                format: (props) => `set dns name="${props[0]}" source=${props[1]} addr=${props[2]} register=${props[3]}`
                            },
                            setwins: {
                                params: ['name', 'source', 'addr'],
                                format: (props) => `set wins name="${props[0]}" source=${props[1]} addr=${props[2]}`
                            },
                            show: {
                                params: ['interface', 'config'],
                                format: (props) => `show ${props[0]} ${props[1]}`
                            }
                        }
                    },
                    wlan: {
                        commands: {
                            connect: {
                                params: ['ssid', 'name'],
                                format: (props) => `connect ssid="${props[0]}" name="${props[1]}"`
                            },
                            disconnect: {
                                params: [],
                                format: () => 'disconnect'
                            },
                            show: {
                                params: ['profiles', 'interfaces', 'networks', 'drivers'],
                                format: (props) => `show ${props.join(' ')}`
                            },
                            set: {
                                params: ['profile', 'ssid', 'key'],
                                format: (props) => `set ${props[0]} name="${props[1]}" key="${props[2]}"`
                            }
                        }
                    },
                    advfirewall: {
                        commands: {
                            set: {
                                params: ['allprofiles', 'publicprofile', 'privateprofile', 'domainprofile'],
                                format: (props) => `set ${props.join(' ')}`
                            },
                            show: {
                                params: ['allprofiles', 'publicprofile', 'privateprofile', 'domainprofile'],
                                format: (props) => `show ${props.join(' ')}`
                            }
                        }
                    }
                };
            
                // Validate props
                if (!Array.isArray(props) || props.length < 2) {
                    throw new Error('Invalid command properties.');
                }
            
                const context = props[0].toLowerCase();
                const command = props[1].toLowerCase();
                const parameters = props.slice(2);
            
                // Check if context and command are valid
                if (!contexts[context] || !contexts[context].commands[command]) {
                    throw new Error('Invalid context or command.');
                }
            
                const commandObj = contexts[context].commands[command];
                const paramValues = parameters.slice(0, commandObj.params.length);
                const formattedCommand = commandObj.format(paramValues);
            
                const cmd = `netsh ${context} ${command} ${formattedCommand}`;
                return Buffer.from(cmd).toString('base64');
            }
        }
    }
};