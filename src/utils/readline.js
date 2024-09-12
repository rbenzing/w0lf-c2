const { createInterface } = require('node:readline');
/**
 * Processes and shows the input on the console
 */
const startInputListener = async () => {
    return createInterface({
        input: process.stdin,
        output: process.stdout,
        prompt: "\x1b[33mEnter command > \x1b[0m"
    });
};

module.exports = {
    startInputListener
};