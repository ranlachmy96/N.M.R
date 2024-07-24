const express = require('express');
const path = require('path');
const logger = require('morgan');
const app = express();
const { reportsRouter } = require('./routers/reportRouter');
const port = process.argv[2] || process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/data', reportsRouter);
app.use(logger('dev'));

let server;

const startServer = (port) => {
    server = app.listen(port, () => console.log(`Express server is running on port ${port}`))
        .on('error', (error) => {
            if (error.code === 'EADDRINUSE') {
                console.log(`Port ${port} is already in use. Trying another port...`);
                shutdown(() => startServer(port + 2)); // Try the next port
            } else {
                console.error(`Server error: ${error}`);
            }
        });
};

// Graceful shutdown
const shutdown = (callback) => {
    if (server) {
        console.log('Shutting down server...');
        server.close(() => {
            console.log('Server closed.');
            if (callback) callback();
        });
    }
};

process.on('SIGINT', () => shutdown(() => process.exit(0)));
process.on('SIGTERM', () => shutdown(() => process.exit(0)));

startServer(port);
