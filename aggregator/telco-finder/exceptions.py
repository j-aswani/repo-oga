class TelcoFinderException(Exception):
    status_code = None
    error = None
    description = None

    def __init__(self, description=None):
        if description is not None:
            self.description = description


class ServerErrorException(TelcoFinderException):
    status_code = 500
    error = 'server_error'
    description = 'Internal server error'


class InvalidAccessTokenException(ServerErrorException):
    def __init__(self, message):
        super().__init__(message)


class InvalidRequestException(TelcoFinderException):
    status_code = 400
    error = 'invalid_request'
    description = 'Invalid request'


class NotFoundException(TelcoFinderException):
    status_code = 404
    error = 'invalid_request'
    description = 'Resource not found'
