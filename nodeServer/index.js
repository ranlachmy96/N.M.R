const express = require('express')
const path = require('path')

const logger = require('morgan') // NOTE: for debugging
const app = express()
const port =process.argv[2] || process.env.PORT || 3000
const { reportsRouter } = require('./routers/reportRouter')


app.use(express.static(path.join(__dirname, 'public')))

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use('/data', reportsRouter)

app.use(logger('dev'))

app.listen(port, () => console.log(`Express server is running on port ${port}`))