import logging
from collections import OrderedDict

import ujson as json
from django.conf import settings
from django.http.response import HttpResponse
from oauthlib.oauth2.rfc6749 import errors
from rest_framework.exceptions import MethodNotAllowed, ParseError, \
    UnsupportedMediaType, NotAcceptable

from aggregator.utils.utils import uncapitalize_first, undot, dot, \
    capitalize_first

logger = logging.getLogger(settings.LOGGING_PREFIX)


class AggregatorException(Exception):

    def __init__(self, response_code, log_level, code, message=None, description=None):
        super().__init__(message)
        self.response_code = response_code
        self.log_level = log_level
        self.code = code
        self.description = description or message


class ServerErrorException(AggregatorException):

    def __init__(self, message):
        super().__init__(500,
                         logging.ERROR,
                         'server_error',
                         message,
                         'Internal server error')


class JWTException(Exception):

    def __init__(self, message, **kwargs):
        super().__init__(f'Invalid JWT: {message}.', **kwargs)


# ### oauthlib errors ### #

# warning: monkey patching (backward compatibility)

def format_description_error(description):
    return undot(uncapitalize_first(description)) if settings.ERROR_DESCRIPTION_FORMAT == 'lowercase' else dot(capitalize_first(description))


def patched__init(self, description=None, uri=None, state=None, status_code=None, request=None):

    # patching
    if description is not None:
        self.description = format_description_error(description)
    elif hasattr(self, 'description'):
        self.description = format_description_error(getattr(self, 'description'))
    # end patching

    message = '(%s) %s' % (self.error, self.description)
    if request:
        message += ' ' + repr(request)
    super(errors.OAuth2Error, self).__init__(message)

    self.uri = uri
    self.state = state

    if status_code:
        self.status_code = status_code

    if request:
        self.redirect_uri = request.redirect_uri
        self.client_id = request.client_id
        self.scopes = request.scopes
        self.response_type = request.response_type
        self.response_mode = request.response_mode
        self.grant_type = request.grant_type
        if not state:
            self.state = request.state
    else:
        self.redirect_uri = None
        self.client_id = None
        self.scopes = None
        self.response_type = None
        self.response_mode = None
        self.grant_type = None


errors.OAuth2Error.__init__ = patched__init


class ServerError(errors.FatalClientError):
    status_code = 500
    error = 'server_error'
    description = 'Internal server error.'


class NotFoundError(errors.FatalClientError):
    status_code = 404
    error = 'invalid_request'

    def __init__(self, resource, **kwargs):
        super().__init__(description=f'Resource {resource} does not exist.', **kwargs)


class InvalidParameterValueError(errors.InvalidRequestError):

    def __init__(self, parameter=None, message=None, **kwargs):
        if parameter:
            super().__init__(description=f'Invalid {parameter} parameter value' + ('.' if message is None else f': {message}.'), **kwargs)
        else:
            super().__init__(description=f'Invalid parameter value' + ('.' if message is None else f': {message}.'), **kwargs)


class MissingParameterError(errors.InvalidRequestError):

    def __init__(self, parameter, **kwargs):
        super().__init__(description=f'Missing {parameter} parameter.', **kwargs)


class MatchingParameterError(errors.InvalidRequestError):

    def __init__(self, parameter, **kwargs):
        super().__init__(description=f'Mismatching {parameter}.', **kwargs)


class NoUserError(errors.OAuth2Error):
    error = 'access_denied'
    description = 'Unknown user.'


class CorrelatedOAuth2Error(errors.CustomOAuth2Error):

    def __init__(self, error, correlation_id, **kwargs):
        super().__init__(error, **kwargs)
        self.correlation_id = correlation_id

    @property
    def json(self):
        value = dict(self.twotuples)
        if self.correlation_id is not None:
            value['correlation_id'] = self.correlation_id

        return json.dumps(value, escape_forward_slashes=False)


class InvalidSignatureError(errors.InvalidRequestFatalError):
    description = 'Invalid signature.'


class UnavailableSignatureError(errors.InvalidRequestFatalError):
    description = 'Unavailable signature key.'


class ExpiredLoginHintTokenError(errors.OAuth2Error):
    error = 'expired_login_hint_token'


class UnknownUserIdError(errors.OAuth2Error):
    error = 'unknown_user_id'


class AuthorizationPendingError(errors.OAuth2Error):
    error = 'authorization_pending'


def api_exception_handler(exc, context):
    if isinstance(exc, errors.OAuth2Error):
        return HttpResponse(exc.json, content_type='application/json', status=exc.status_code)
    elif isinstance(exc, MethodNotAllowed):
        return api_exception_handler(errors.CustomOAuth2Error('invalid_request', status_code=405, description=exc.detail), context)
    elif isinstance(exc, ParseError) or isinstance(exc, UnsupportedMediaType):
        return api_exception_handler(InvalidParameterValueError(exc.detail), context)
    elif isinstance(exc, NotAcceptable):
        return api_exception_handler(errors.CustomOAuth2Error('invalid_request', status_code=406, description=exc.detail), context)
    else:
        return api_exception_handler(errors.CustomOAuth2Error('server_error', status_code=500), context)


def log_exception(exception):
    logger.error('Exception', extra={'data': OrderedDict([('class', exception.__class__.__name__), ('message', str(exception.args[0]))])})