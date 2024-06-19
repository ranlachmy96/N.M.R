const { spawn } = require('child_process');

exports.startServer = (port) => {
    const server = spawn('node', ['index.js', port]);

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
