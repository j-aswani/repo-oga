import logging
from json.decoder import JSONDecoder

import requests
import ujson as json
from django.conf import settings
from django.http.response import HttpResponse
from django.urls.base import reverse
from django.views.generic.base import View
from oauthlib.oauth2.rfc6749.endpoints.metadata import MetadataEndpoint
from oauthlib.oauth2.rfc6749.errors import InvalidRequestFatalError
from oauthlib.oauth2.rfc6749.tokens import random_token_generator

from authserver.oauth2.baikal.server import BaikalServer
from authserver.oauth2.baikal.tokens import access_token_expires_in, jwt_token_generator
from authserver.oauth2.baikal.validators import BaikalRequestValidator
from authserver.utils.jwk import JWKManager
from authserver.utils.parsers import object_pairs_hook
from authserver.utils.views import publish_to_middleware

logger = logging.getLogger(settings.LOGGING_PREFIX)

validator = BaikalRequestValidator()
server = BaikalServer(validator, token_expires_in=access_token_expires_in,
                      token_generator=jwt_token_generator, refresh_token_generator=random_token_generator)


def build_response(headers, body, status):
    response = HttpResponse(body, status=status)
    for header in headers:
        response[header] = headers[header]
    return response


def get_json_data(data):
    try:
        decoder = JSONDecoder(object_pairs_hook=object_pairs_hook)
        return decoder.decode(data)
    except Exception as e:
        raise Exception(f'Invalid JSON: {e.args[0]}')


def get_body_from_request(request):
    try:
        content_type = request.headers.get('Content-Type', None)
        if content_type.startswith('application/json'):
            return get_json_data(request.body.decode('utf-8'))
        elif content_type.startswith('application/x-www-form-urlencoded'):
            return request.body
    except Exception as e:
        raise InvalidRequestFatalError(description=str(e.args[0]))

    raise InvalidRequestFatalError(description='Invalid content type')


@publish_to_middleware(response_content_type='text/html', operation='AUTHORIZE')
class AuthorizeView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._authorization_endpoint = server

    def get(self, request):
        headers, body, status = self._authorization_endpoint.create_authentication_response(request.get_full_path(), 'GET')
        return build_response(headers, body, status)


@publish_to_middleware(response_content_type='application/json', operation='CIBA')
class CibaAuthorizeView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._authorization_endpoint = server

    def post(self, request):
        headers, body, status = self._authorization_endpoint.create_ciba_authorization_response(request.get_full_path(), 'POST', get_body_from_request(request), request.headers)
        return build_response(headers, body, status)


@publish_to_middleware(response_content_type='application/json', operation='TOKEN')
class TokenView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._token_endpoint = server

    def post(self, request):
        headers, body, status = self._token_endpoint.create_token_response(request.get_full_path(), 'POST', get_body_from_request(request), request.headers)
        return build_response(headers, body, status)


@publish_to_middleware(response_content_type='application/json', operation='REVOKE')
class RevokeView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._revoke_endpoint = server

    def post(self, request):
        headers, body, status = self._revoke_endpoint.create_revocation_response(request.get_full_path(), 'POST', get_body_from_request(request), request.headers)
        return build_response(headers, body, status)


@publish_to_middleware(response_content_type='application/json', operation='INTROSPECT')
class IntrospectView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._instrospection_endpoint = server

    def post(self, request):
        headers, body, status = self._instrospection_endpoint.create_introspect_response(request.get_full_path(), 'POST', get_body_from_request(request), request.headers)
        return build_response(headers, body, status)


@publish_to_middleware(response_content_type='application/json', operation='OIDC_CONFIGURATION')
class MetadataView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._metadata_endpoint = server

    def get(self, request):
        claims = {
            'issuer': settings.AUTHSERVER_ISSUER,
            'authorization_endpoint': settings.AUTHSERVER_HOST + reverse('authserver-authorize'),
            'backchannel_authentication_endpoint': settings.AUTHSERVER_HOST + reverse('authserver-bc-authorize'),
            'token_endpoint': settings.AUTHSERVER_HOST + reverse('authserver-token'),
            'revocation_endpoint': settings.AUTHSERVER_HOST + reverse('authserver-revoke'),
            'introspection_endpoint': settings.AUTHSERVER_HOST + reverse('authserver-introspect'),
            'jwks_uri': settings.AUTHSERVER_JWKS_URI or settings.AUTHSERVER_HOST + reverse('jwkset'),
            'userinfo_endpoint': settings.AUTHSERVER_HOST + reverse('userinfo')
        }

        claims.update(**settings.DISCOVERY)

        endpoint = MetadataEndpoint([self._metadata_endpoint], claims=claims, raise_errors=False)
        headers, body, status = endpoint.create_metadata_response(request.get_full_path(), 'GET', None, request.headers)
        return build_response(headers, body, status)


@publish_to_middleware(response_content_type='application/json', operation='JWKSET')
class JWKSetView(View):

    def get(self, request):
        try:
            jwkset = {"keys": [JWKManager().export_public()]}
            return HttpResponse(content=json.dumps(jwkset, indent=4), content_type='application/json', status=200)
        except Exception as e:
            return HttpResponse(content=str(e.args[0]), status=requests.codes.server_error)


@publish_to_middleware(response_content_type='application/json', operation='USERINFO')
class UserInfoView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._userinfo_endpoint = server

    def get(self, request):
        headers, body, status = self._userinfo_endpoint.create_userinfo_response(request.get_full_path(), 'GET', None, request.headers)
        return build_response(headers, body, status)
