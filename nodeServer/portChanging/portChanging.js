/** *************************************************************************************
 Importing the `spawn` function from the `child_process` module to create child processes 
 and the `path` module to handle file paths.
 ************************************************************************************** */
const { spawn } = require('child_process');
const path = require('path');

/** *************************************************************************************
 Defines the `startServer` function which starts a server on the specified port.
 Resolves the absolute path to the 'index.js' file located one directory above 
 the current directory.
 Spawns a new Node.js process to run the 'index.js' script with the given port.
 Handles errors encountered when attempting to start the server, such as port in use.
 If the port is in use, tries to start the server on the next available port.
 Logs data received from the server's standard output (stdout).    
 Logs when the server process exits, along with the exit code.
 ************************************************************************************** */
exports.startServer = (port) => {
    const indexPath = path.resolve(__dirname, '../index.js');
    const server = spawn('node', [indexPath, port]);

    server.on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
          console.log(`Port ${port} is already in use. Trying another port...`);
          startServer(port + 1);
        } else {
          console.error(`Server error: ${error}`);
        }
      });

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