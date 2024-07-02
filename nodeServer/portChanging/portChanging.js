const { spawn } = require('child_process');
const path = require('path');

exports.startServer = (port) => {
    const indexPath = path.resolve(__dirname, '../index.js');
    const server = spawn('node', [indexPath, port]);

    server.stdout.on('data', (data) => {
        console.log(`stdout: ${data}`);
    });

    server.stderr.on('data', (data) => {
        console.error(`stderr: ${data}`);
    });

    server.on('close', (code) => {
        console.log(`child process exited with code ${code}`);
    });
}
