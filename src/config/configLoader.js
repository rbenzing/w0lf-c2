const fs = require('fs');
const path = require('path');

let config = {};

const loadConfig = () => {
  try {
    const configPath = path.resolve(__dirname, 'config.json');
    const configFile = fs.readFileSync(configPath, 'utf8');
    config = JSON.parse(configFile);
  } catch (error) {
    console.error('Error loading configuration file:', error);
    process.exit(1);
  }
};

loadConfig();

module.exports = config;