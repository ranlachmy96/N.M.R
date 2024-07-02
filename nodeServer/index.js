const express = require('express')
const path = require('path')
// const portChanging = require('./portChanging/portChanging')

const logger = require('morgan') // NOTE: for debugging
const app = express()
const port =process.argv[2] || process.env.PORT || 3000


app.use(express.static(path.join(__dirname, 'public')))

app.get('/', (req, res) => {
    // Prepare the data you want to send
    const data = {
        message: 'Hello, this is data from the server!',
        date: new Date(),
    };
    res.json(data);
});

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.use(logger('dev'))

app.listen(port, () => console.log(`Express server is running on port ${port}`))