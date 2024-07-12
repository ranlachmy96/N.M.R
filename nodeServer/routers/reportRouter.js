const { Router } = require('express')
const { reportsController } = require('../controllers/reportsController')
const reportsRouter = new Router()

reportsRouter.get('/', reportsController.getReports)
reportsRouter.get('/:reportId', reportsController.getReportById)
reportsRouter.post('/', reportsController.addReport) 
reportsRouter.put('/:reportId', reportsController.updateReport) 
reportsRouter.delete('/:reportId', reportsController.deleteReport) 

module.exports = { reportsRouter }