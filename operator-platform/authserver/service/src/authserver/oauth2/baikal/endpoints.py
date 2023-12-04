import logging

import ujson as json
from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import utils
from oauthlib.oauth2.rfc6749.endpoints.authorization import AuthorizationEndpoint
from oauthlib.oauth2.rfc6749.endpoints.base import catch_errors_and_unavailability, BaseEndpoint
from oauthlib.oauth2.rfc6749.endpoints.introspect import IntrospectEndpoint
from oauthlib.oauth2.rfc6749.endpoints.revocation import RevocationEndpoint
from oauthlib.oauth2.rfc6749.endpoints.token import TokenEndpoint
from oauthlib.oauth2.rfc6749.errors import UnsupportedTokenTypeError
from oauthlib.openid import UserInfoEndpoint

from authserver.middleware.baikal import BaikalMiddleware, log_metric
from authserver.utils.exceptions import ServerError

log = logging.getLogger(__name__)


class BaikalAuthorizationEndpoint(AuthorizationEndpoint):

    @catch_errors_and_unavailability
    def create_authentication_response(self, uri, http_method='GET'):
        request = Request(uri, http_method=http_method, body=None, headers=None)
        BaikalMiddleware.set_oauth_request(BaikalMiddleware.get_current_request(), request)
        request.scopes = utils.scope_to_list(request.scope)
        response_type_handler = self.response_types.get(request.response_type, self.default_response_type_handler)
        headers, body, status = response_type_handler.create_authentication_response(request, self.default_token_type)
        return headers, body, status


class BaikalCibaAuthorizationEndpoint(BaseEndpoint):

    def __init__(self, granter, ciba_default_token_type):
        BaseEndpoint.__init__(self)
        self.granter = granter
        self._ciba_default_token_type = ciba_default_token_type

    @property
    def ciba_default_token_type(self):
        return self._ciba_default_token_type

    @catch_errors_and_unavailability
    def create_ciba_authorization_response(self, uri, http_method='POST', body=None, headers=None):
        request = Request(uri, http_method=http_method, body=body, headers=headers)
        BaikalMiddleware.set_oauth_request(BaikalMiddleware.get_current_request(), request)
        request.scopes = utils.scope_to_list(request.scope)
        headers, body, status = self.granter.create_ciba_authorization_response(request, self.ciba_default_token_type)
        log_metric('ok')
        return headers, body, status


class BaikalTokenEndpoint(TokenEndpoint):

    @catch_errors_and_unavailability
    def create_token_response(self, uri, http_method='POST', body=None, headers=None, credentials=None, grant_type_for_scope=None, claims=None):
        request = Request(uri, http_method=http_method, body=body, headers=headers)
        BaikalMiddleware.set_oauth_request(BaikalMiddleware.get_current_request(), request)

        self.validate_token_request(request)
        request.scopes = utils.scope_to_list(request.scope)

        request.extra_credentials = credentials
        if grant_type_for_scope:
            request.grant_type = grant_type_for_scope

        if claims:
            request.claims = claims

        grant_type_handler = self.grant_types.get(request.grant_type,  self.default_grant_type_handler)
        headers, body, status = grant_type_handler.create_token_response(request, self.default_token_type)
        log_metric('ok')
        return headers, body, status


class BaikalRevocationEndpoint(RevocationEndpoint):

    @catch_errors_and_unavailability
    def create_revocation_response(self, uri, http_method='POST', body=None, headers=None):
        request = Request(uri, http_method=http_method, body=body, headers=headers)
        BaikalMiddleware.set_oauth_request(BaikalMiddleware.get_current_request(), request)
        self.validate_revocation_request(request)
        self.request_validator.revoke_token(request.token, request.token_type_hint, request)
        log_metric('ok')
        return {}, '', 200

    def _raise_on_unsupported_token(self, request):
        if request.token_type_hint and (request.token_type_hint not in self.supported_token_types):
            raise UnsupportedTokenTypeError(request=request)


class BaikalIntrospectEndpoint(IntrospectEndpoint):

    @catch_errors_and_unavailability
    def create_introspect_response(self, uri, http_method='POST', body=None, headers=None):

        resp_headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }

        request = Request(uri, http_method, body, headers)
        BaikalMiddleware.set_oauth_request(BaikalMiddleware.get_current_request(), request)

        self.validate_introspect_request(request)

        claims = self.request_validator.introspect_token(request.token, request.token_type_hint, request)
        if claims is None:
            claims = dict(active=False)
            log_metric('not_found')
        else:
            log_metric('ok')
            claims = dict(active=True, **claims)
        return resp_headers, json.dumps(claims, escape_forward_slashes=False), 200


class BaikalUserInfoEndpoint(UserInfoEndpoint):

    @catch_errors_and_unavailability
    def create_userinfo_response(self, uri, http_method='GET', body=None, headers=None):
        request = Request(uri, http_method, body, headers)
        BaikalMiddleware.set_oauth_request(BaikalMiddleware.get_current_request(), request)

        request.scopes = ["openid"]
        self.validate_userinfo_request(request)

        claims = self.request_validator.get_userinfo_claims(request)
        if "sub" not in claims:
            log.error('Userinfo MUST have "sub" for %r.', request)
            raise ServerError("No sub claim")

        resp_headers = {
            'Content-Type': 'application/json'
        }
        body = json.dumps(claims)

        log_metric('ok')
        return resp_headers, body, 200
