/**
 * The client object definition
 * @typedef {{
        sessionId: String,
        socket: Socket,
        address: String,
        lastSeen: Date,
        active: Boolean,
        buffer: String,
        waiting: Boolean,
        version: String,
        type: String,
        platform: String, 
        arch: String, 
        osver: String, 
        hostname: String
    }} Client
 */

/**
 * The beacon response object definition
 * @typedef {{
        version: String,
        arch: String,
        hostname: String,
        type: String,
        platform: String,
        osver: String,
        beacon: Boolean
    }} BeaconResponse
 */

/**
 * The command object definition
 * @typedef {{
        name: String,
        method: String,
        description: String,
        parameters: Object
        handler: Function
    }} Command
 */

/**
 * The plugin object definition
 * @typedef {{
        name: String,
        type: String,
        description: String,
        commands: Command[]
    }} Plugin
 */