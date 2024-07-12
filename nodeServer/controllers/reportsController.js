const { findReports, retrieveReport, createReport, updateReport, deleteReport } = require('../repositories/reportsRepository')
const { EntityNotFoundError, PropertyNotFoundError, BadRequestError } = require('../errors/errors')

exports.reportsController = {
  async getReports (req, res, next) {
    try {
      const result = {
        status: 200,
        message: '',
        data: await findReports()
      }
      if (result.data.length === 0 || !result.data) throw new EntityNotFoundError('Reports')
      res.status(result.status)
      res.json(result.message || result.data)
    } catch (error) {
      next(error)
    }
  },
  async getReportById (req, res, next) {
    const { reportId } = req.params
    try {
      const result = {
        status: 200,
        message: '',
        data: await retrieveReport(reportId)
      }
      if (result.data.length === 0 || !result.data) throw new EntityNotFoundError('Report')
      res.status(result.status)
      res.json(result.message || result.data)
    } catch (error) {
      next(error)
    }
  },

  async addReport (req, res, next) {
    const report = req.body
    // report.reportId = ++counter
    try {
      if (Object.keys(req.body).length === 0) throw new BadRequestError('create')
      const { email } = report
      if (!email) throw new PropertyNotFoundError('report - missing arguments')
      const result = {
        status: 201,
        message: '',
        data: await createReport(report)
      }
      // res.status(result.status)
      // res.json(result.message || result.data)
      res.redirect('/')
    } catch (error) {
      next(error)
    }
  },

  async updateReport (req, res, next) {
    const { body: report, params: { reportId } } = req
    try {
      if (Object.keys(req.body).length === 0) throw new BadRequestError('update')
      const result = {
        status: 200,
        message: '',
        data: await updateReport(reportId, report)
      }
      if (!result.data || result.data.length === 0) throw new EntityNotFoundError(`Request with id <${reportId}>`)
      res.status(result.status)
      res.json(result.message || result.data)
    } catch (error) {
      next(error)
    }
  },

  async deleteReport (req, res, next) {
    const { reportId } = req.params
    try {
      const result = {
        status: 200,
        message: '',
        data: await deleteReport(reportId)
      }
      if (!result.data || result.data.length === 0) throw new EntityNotFoundError(`Request with id <${reportId}>`)
      res.status(result.status)
      res.json(result.message || result.data)
    } catch (error) {
      next(error)
    }
  }
}
