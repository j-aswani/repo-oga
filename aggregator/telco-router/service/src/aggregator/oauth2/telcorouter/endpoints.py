import logging

from django.conf import settings
from django.urls import reverse
from oauthlib.common import Request
from oauthlib.oauth2 import BearerToken
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749 import utils
from oauthlib.oauth2.rfc6749.endpoints.authorization import AuthorizationEndpoint
from oauthlib.oauth2.rfc6749.endpoints.base import catch_errors_and_unavailability, BaseEndpoint
from oauthlib.oauth2.rfc6749.endpoints.token import TokenEndpoint
from oauthlib.oauth2.rfc6749.errors import UnsupportedGrantTypeError

from aggregator.clients.telco_finder import TelcoFinderClient
from aggregator.middleware.telcorouter import AggregatorMiddleware, log_metric
from aggregator.utils.http import do_request_call

log = logging.getLogger(__name__)


class AggregatorAuthorizationEndpoint(AuthorizationEndpoint):

    @catch_errors_and_unavailability
    def create_authentication_response(self, uri, http_method='GET'):
        request = Request(uri, http_method=http_method, body=None, headers=None)
        AggregatorMiddleware.set_oauth_request(AggregatorMiddleware.get_current_request(), request)
        request.scopes = utils.scope_to_list(request.scope)
        response_type_handler = self.response_types.get(request.response_type, self.default_response_type_handler)
        headers, body, status = response_type_handler.create_authentication_response(request)
        return headers, body, status

    @catch_errors_and_unavailability
    def create_callback_response(self, uri, http_method='GET'):
        request = Request(uri, http_method=http_method, body=None, headers=None)
        AggregatorMiddleware.set_oauth_request(AggregatorMiddleware.get_current_request(), request)
        response_type_handler = self.response_types.get(request.response_type, self.default_response_type_handler)
        headers, body, status = response_type_handler.create_callback_response(request, self.default_token_type)
        return headers, body, status


class AggregatorTokenEndpoint(TokenEndpoint):

    @catch_errors_and_unavailability
    def create_token_response(self, uri, http_method='POST', body=None, headers=None, credentials=None, grant_type_for_scope=None, claims=None):
        request = Request(uri, http_method=http_method, body=body, headers=headers)
        AggregatorMiddleware.set_oauth_request(AggregatorMiddleware.get_current_request(), request)

        self.validate_token_request(request)
        request.scopes = utils.scope_to_list(request.scope)

        request.extra_credentials = credentials
        if grant_type_for_scope:
            request.grant_type = grant_type_for_scope

        if claims:
            request.claims = claims

        grant_type_handler = self.grant_types.get(request.grant_type,  self.default_grant_type_handler)
        if grant_type_handler is None:
            raise UnsupportedGrantTypeError()
        headers, body, status = grant_type_handler.create_token_response(request, self.default_token_type)
        log_metric('ok')
        return headers, body, status


class AggregatorApiEndpoint(BaseEndpoint):

    def __init__(self, request_validator):
        self.bearer = BearerToken(request_validator, None, None, None)
        self.request_validator = request_validator
        BaseEndpoint.__init__(self)

    @catch_errors_and_unavailability
    def create_api_response(self, uri, http_method='GET', body=None, headers=None):
        request = Request(uri, http_method, body, headers)
        self.validate_api_request(request)

        api_host = request.token['routing'][TelcoFinderClient.FIELD_APIS]
        aggregator_api_prefix = reverse('api')
        real_path = uri.removeprefix(aggregator_api_prefix)
        url = api_host + ('/' if not api_host.endswith("/") and not real_path.startswith("/") else "") + real_path

        headers = dict(headers)
        headers['Authorization'] = f"Bearer {request.token['access_token']}"

        response = do_request_call('Routing API', http_method, url,
                                   headers=headers, data=body, verify=settings.API_SSL_VERIFICATION, timeout=settings.API_HTTP_TIMEOUT)

        log_metric(str(response.status_code), additional_data={"host": api_host, "method": http_method, "path": real_path})

        return response.headers, response.text, response.status_code

    def validate_api_request(self, request):
        if not self.bearer.validate_request(request):
            raise errors.InvalidTokenError()
