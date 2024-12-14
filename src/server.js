/**
 *                                  ,--,                                               
 *                               ,---.'|                                               
 *            .---.    ,----..   |   | :       ,---,.          ,----..        ,----,   
 *           /. ./|   /   /   \  :   : |     ,'  .' |         /   /   \     .'   .' \  
 *       .--'.  ' ;  /   .     : |   ' :   ,---.'   |        |   :     :  ,----,'    | 
 *      /__./ \ : | .   /   ;.  \;   ; '   |   |   .'        .   |  ;. /  |    :  .  ; 
 *  .--'.  '   \' ..   ;   /  ` ;'   | |__ :   :  :          .   ; /--`   ;    |.'  /  
 * /___/ \ |    ' ';   |  ; \ ; ||   | :.'|:   |  |-,        ;   | ;      `----'/  ;   
 * ;   \  \;      :|   :  | ; | ''   :    ;|   :  ;/|        |   : |        /  ;  /    
 *  \   ;  `      |.   |  ' ' ' :|   |  ./ |   |   .'        .   | '___    ;  /  /-,   
 *   .   \    .\  ;'   ;  \; /  |;   : ;   '   :  '          '   ; : .'|  /  /  /.`|   
 *    \   \   ' \ | \   \  ',  / |   ,/    |   |  |          '   | '/  :./__;      :   
 *     :   '  |--"   ;   :    /  '---'     |   :  \          |   :    / |   :    .'    
 *      \   \ ;       \   \ .'             |   | ,'           \   \ .'  ;   | .'       
 *       '---"         `---`               `----'              `---`    `---'          
 *    AUTHOR: Russell Benzing                             
 *    VERSION: 0.3.1
 *    LICENSE: GPL-3.0
 */
// ---------------------------------------------------------------------------------
const { startServer, shutdown } = require('./modules/server');
const config = require('./modules/config');

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Load Channel
switch (config.server.method) {
    case "tcp":
        const { listenSocketServer } = require('./channels/socket');
        listenSocketServer();
        break;
    case "tls":
        const { startTLSServer } = require('./channels/tls');
        startTLSServer();
        break;
    case "http2":
        const { startHTTP2Server } = require('./channels/http2');
        startHTTP2Server();
        break;
    case "udp":
        const { startUDPServer } = require('./channels/udp');
        startUDPServer();
        break;
    default:
        shutdown();
}

// Howel at the moon
startServer();