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

from aggregator.oauth2.telcorouter.server import AggregatorServer
from aggregator.oauth2.telcorouter.tokens import access_token_expires_in, jwt_token_generator
from aggregator.oauth2.telcorouter.validators import AggregatorRequestValidator
from aggregator.utils.jwk import JWKManager
from aggregator.utils.parsers import object_pairs_hook
from aggregator.utils.views import publish_to_middleware

logger = logging.getLogger(settings.LOGGING_PREFIX)

validator = AggregatorRequestValidator()
server = AggregatorServer(validator, token_expires_in=access_token_expires_in,
                      token_generator=jwt_token_generator)


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


@publish_to_middleware(response_content_type='text/html', operation='AUTHORIZE')
class AuthorizeCallbackView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._authorization_endpoint = server

    def get(self, request):
        headers, body, status = self._authorization_endpoint.create_callback_response(request.get_full_path(), 'GET')
        return build_response(headers, body, status)


@publish_to_middleware(response_content_type='application/json', operation='TOKEN')
class TokenView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._token_endpoint = server

    def post(self, request):
        headers, body, status = self._token_endpoint.create_token_response(request.get_full_path(), 'POST', get_body_from_request(request), request.headers)
        return build_response(headers, body, status)


@publish_to_middleware(response_content_type='application/json', operation='METADATA')
class MetadataView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._metadata_endpoint = server

    def get(self, request):
        claims = {
            'issuer': settings.AGGREGATOR_ISSUER,
            'authorization_endpoint': settings.AGGREGATOR_HOST + reverse('aggregator-authorize'),
            'token_endpoint': settings.AGGREGATOR_HOST + reverse('aggregator-token'),
            'jwks_uri': settings.AGGREGATOR_JWKS_URI or settings.AGGREGATOR_HOST + reverse('jwkset')
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


@publish_to_middleware(response_content_type='application/json', operation='API')
class ApiView(View):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._api_endpoint = server

    def dispatch(self, request, *args, **kwargs):
        headers, body, status = self._api_endpoint.create_api_response(request.get_full_path(), request.method, request.body, request.headers)
        return build_response(headers, body, status)
