const http2 = require('node:http2');

const startHTTP2Server = () => {
    server = http2.createSecureServer({
        key: fs.readFileSync(path.join(__dirname, 'server.key')),
        cert: fs.readFileSync(path.join(__dirname, 'server.cert')),
    }, (req, res) => {
        // finish
    });
};

module.exports = {
    startHTTP2Server
};