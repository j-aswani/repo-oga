import logging
import uuid
from collections import OrderedDict

from django.conf import settings
from django.http.response import HttpResponseRedirect, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from oauthlib.oauth2.rfc6749.errors import FatalClientError, OAuth2Error
from rest_framework.request import Request

from authserver.utils.exceptions import ServerError
from authserver.utils.http import render_response

logger = logging.getLogger(settings.LOGGING_PREFIX)

try:
    from threading import local
except ImportError:
    from django.utils._threading_local import local

_thread_locals = local()


def custom_exception_handler(request, exc):
    if isinstance(exc, FatalClientError) or isinstance(exc, ServerError):
        log_error_metric(exc)
        if getattr(request, 'response_content_type', None) == 'application/json':
            return HttpResponse(exc.json, content_type='application/json', status=exc.status_code)
        else:
            return render_response(request, 'error.html', context={'code': exc.error, 'message': exc.description}, status=exc.status_code)
    elif isinstance(exc, OAuth2Error):
        log_error_metric(exc)
        if getattr(request, 'response_content_type', None) == 'application/json':
            return HttpResponse(exc.json, content_type='application/json', status=exc.status_code)
        else:
            return HttpResponseRedirect(exc.in_uri(exc.redirect_uri))
    else:
        return custom_exception_handler(request, ServerError())


def log_error_metric(error):
    log_metric(error.error, getattr(error, 'description', None))


def log_metric(result, description=None):
    try:
        request = BaikalMiddleware.get_current_request()
        oauth_request = BaikalMiddleware.get_oauth_request(request)

        data = OrderedDict([('op',  getattr(request, 'operation', 'NA')), ('result', result)])
        if oauth_request:
            for field in ['client_name', 'response_type', 'grant_type', 'scopes', 'acr', 'amr']:
                value = getattr(oauth_request, field, None)
                if value is None:
                    auth = getattr(oauth_request, 'auth', {}) or {}
                    value = auth.get(field, None)
                if value is not None:
                    data[field] = value

        if description:
            data['result_description'] = description

        logger.info('Metric', extra={'data': data})
    except Exception as e:
        logger.error('Error logging metric: %s', str(e.args[0]))
        raise


class BaikalMiddleware(MiddlewareMixin):

    """
    Baikal middleware. If it is enabled, each request/response will manage parameters.
    """

    BAIKAL_CORRELATOR_HEADER = 'X-Correlator'

    TRANSACTION_ID_FIELD = 'transaction_id'
    CORRELATOR_FIELD = 'baikal_correlator'
    OAUTH_REQUEST_FIELD = 'oauth_request'

    CURRENT_REQUEST = 'current_request'

    def process_request(self, request):
        setattr(_thread_locals, self.CURRENT_REQUEST, request)

        transaction_id = str(uuid.uuid4())

        self.set_transaction(request, transaction_id)

        self.set_correlator(request, request.headers.get(self.BAIKAL_CORRELATOR_HEADER) or transaction_id)

        return None

    def process_view(self, request, view_func, view_args, view_kwargs):
        try:
            request.response_content_type = getattr(view_func, 'response_content_type', 'text/html')
            request.operation = getattr(view_func, 'operation', 'NA')
        except Exception as e:
            logger.error('Error processing view: %s', str(e.args[0]))
        return None

    def process_exception(self, request, exception):
        return custom_exception_handler(request, exception)

    @classmethod
    def get_wsgi_request(cls, request):
        if request is not None:
            return request._request if isinstance(request, Request) else request
        return None

    @classmethod
    def set_oauth_request(cls, request, oauth_request):
        if request is not None:
            request = cls.get_wsgi_request(request)
            setattr(request, cls.OAUTH_REQUEST_FIELD, oauth_request)

    @classmethod
    def get_oauth_request(cls, request):
        if request is not None:
            request = cls.get_wsgi_request(request)
            return getattr(request, cls.OAUTH_REQUEST_FIELD, None)
        return None

    @classmethod
    def set_correlator(cls, request, correlator):
        if request is not None:
            request = cls.get_wsgi_request(request)
            setattr(request, cls.CORRELATOR_FIELD, correlator)

    @classmethod
    def get_correlator(cls, request):
        if request is not None:
            request = cls.get_wsgi_request(request)
            return getattr(request, cls.CORRELATOR_FIELD, None)
        return None

    @classmethod
    def set_transaction(cls, request, transacrion):
        if request is not None:
            request = cls.get_wsgi_request(request)
            setattr(request, cls.TRANSACTION_ID_FIELD, transacrion)

    @classmethod
    def get_transaction(cls, request):
        if request is not None:
            request = cls.get_wsgi_request(request)
            return getattr(request, cls.TRANSACTION_ID_FIELD, None)
        return None

    @classmethod
    def get_client_id(cls, request):
        if request is not None:
            request = cls.get_wsgi_request(request)
            oauth_request = cls.get_oauth_request(request)
            if oauth_request is not None:
                return getattr(oauth_request, 'client_id', None)
        return None

    @classmethod
    def get_user(cls, request):
        user = None
        if request is not None:
            request = cls.get_wsgi_request(request)
            oauth_request = cls.get_oauth_request(request)
            if oauth_request is not None:
                user = getattr(oauth_request, 'uid', None)
                if hasattr(oauth_request, 'auth'):
                    user = oauth_request.auth.get('uid', None)
        return user

    @classmethod
    def get_current_request(cls):
        return getattr(_thread_locals, cls.CURRENT_REQUEST, None)
