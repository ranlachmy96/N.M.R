/** *************************************************************************************
 Importing the `portChanging` module which is expected to contain functionality for 
 starting a server and managing port changes.
 Determines the port number to be used for the server. It takes the port number from 
 the command-line arguments, environment variables, or defaults to 3002 if neither is provided.
 Starts the server using the `startServer` function from the `portChanging` module and 
 the determined port number.
 ************************************************************************************** */
const portChanging = require('./portChanging')
const newPort = process.argv[2] || process.env.PORT || 3002
portChanging.startServer(newPort)
