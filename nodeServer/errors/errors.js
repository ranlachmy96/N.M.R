class NotFound extends Error {
    constructor (message) {
      super(message)
      this.name = this.constructor.name
      this.status = 404
    }
  }
  
  class EntityNotFoundError extends NotFound {
    constructor (entity) {
      super(`${entity} not found`)
      this.name = this.constructor.name
      this.entity = entity
    }
  }
  
  class PropertyNotFoundError extends NotFound {
    constructor (property) {
      super(`${property} not found`)
      this.name = this.constructor.name
      this.property = property
    }
  }
  
  class BadRequestError extends Error {
    constructor (element) {
      super(`please provide: ${element} in the correct format`)
      this.name = 'BadRequestError'
      this.status = 400
    }
  }
  
  class DuplicateError extends Error {
    constructor (element) {
      super(`please provide: ${element} with unique personal number`)
      this.name = 'DuplicateError'
      this.status = 409
    }
  }
  
  module.exports = {
    EntityNotFoundError,
    PropertyNotFoundError,
    BadRequestError,
    DuplicateError
  }
  