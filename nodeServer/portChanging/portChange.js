const portChanging = require('./portChanging')
const newPort = process.argv[2] || process.env.PORT || 3002
portChanging.startServer(newPort)
