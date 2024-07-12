exports.errorHandler = (error, req, res, next) => {
    res.status(error.status || 500)
    res.json({ message: error.message || 'Internal Server Error' })
}
  