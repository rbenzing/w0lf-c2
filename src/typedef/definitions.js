/**
 * The client object definition
 * @typedef {{
        sessionId: String,
        socket: Socket,
        readline: Interface,
        address: String,
        lastSeen: Date,
        active: Boolean,
        buffer: Buffer<ArrayBufferLike>,
        waiting: Boolean,
        version: String,
        type: String,
        platform: String, 
        arch: String, 
        osver: String, 
        hostname: String
    }} Client
 */