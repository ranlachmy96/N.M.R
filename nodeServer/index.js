const express = require('express')

const logger = require('morgan') // NOTE: for debugging
const app = express()
const port =process.argv[2] || process.env.PORT || 3000

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.use(logger('dev'))

app.listen(port, () => console.log(`Express server is running on port ${port}`))
