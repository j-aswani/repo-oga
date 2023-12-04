import logging
import time
from base64 import urlsafe_b64encode
from collections import OrderedDict
from copy import deepcopy
from urllib.parse import urlencode, parse_qsl

import oauthlib.oauth2.rfc6749.grant_types.base
import requests
import ujson as json
from django.conf import settings
from django.urls import reverse
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS, InvalidJWSSignature
from oauthlib import common
from oauthlib.oauth2 import AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.errors import InvalidRequestFatalError, InvalidClientError, CustomOAuth2Error, MissingClientIdError, InvalidClientIdError, FatalClientError, \
    OAuth2Error, InvalidRequestError, AccessDeniedError, InvalidGrantError
from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant as OAuth2AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.tokens import random_token_generator

from aggregator.clients.oidc import OidcClient
from aggregator.clients.telco_finder import TelcoFinderClient
from aggregator.middleware.telcorouter import AggregatorMiddleware, log_error_metric, log_metric
from aggregator.oauth2.models import ApplicationCollection
from aggregator.utils.exceptions import MissingParameterError, InvalidParameterValueError, JWTException, InvalidSignatureError
from aggregator.utils.http import do_request_call
from aggregator.utils.jwe import build_jwe
from aggregator.utils.jwk import JWKManager
from aggregator.utils.jws import validate_jws_header, get_jws_info, FIELD_ALGORITHM, build_jws
from aggregator.utils.schemas import FIELD_SUB, FIELD_SCOPE, FIELD_KID, FIELD_JTI, FIELD_ISSUER, FIELD_AUDIENCE, FIELD_ISSUED_TIME, FIELD_EXPIRATION, \
    FIELD_REDIRECT_URI, FIELD_ROUTING, FIELD_STATE, FIELD_CODE, FIELD_CLIENT_ID, FIELD_CLIENT_ASSERTION, FIELD_ASSERTION
from aggregator.utils.utils import enrich_object, get_cleaned_data

logger = logging.getLogger(settings.LOGGING_PREFIX)

RESPONSE_TYPE_CODE = 'code'

GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code'
GRANT_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer'


def validate_mandatory_params(request):
    return {}


def validate_parameter_values(request):
    if request.acr_values:
        acr_values = set(request.acr_values.split(' '))
        if len(acr_values - set(settings.DISCOVERY['acr_values_supported'])) > 0:
            raise InvalidParameterValueError('acr_values', request=request)
    if request.max_age:
        try:
            max_age = int(request.max_age)
            if max_age < 0:
                raise InvalidParameterValueError('max_age', request=request)
        except Exception:
            raise InvalidParameterValueError('max_age', request=request)
    return {}


def validate_client_name(request):
    if getattr(request, 'client_name', None) is None:
        if len(request.app[ApplicationCollection.FIELD_NAME]) > 1:
            raise MissingParameterError('client_name', request=request)
        request.client_name = request.app[ApplicationCollection.FIELD_NAME][0]
    elif request.client_name not in request.app[ApplicationCollection.FIELD_NAME]:
        raise InvalidRequestError(description='Mismatching client_name.', request=request)

    return {}


class AggregatorAuthorizationCodeGrantMixin:

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _validate_request_object(self, request):
        if hasattr(request, 'request'):
            try:
                jwstoken = JWS()
                jwstoken.deserialize(request.request)
                alg = jwstoken.jose_header.get(FIELD_ALGORITHM, None)
                if alg not in settings.DISCOVERY['request_object_signing_alg_values_supported']:
                    raise JWTException('Invalid alg value')
                if alg == 'none':
                    payload = json.loads(jwstoken.objects['payload'])
                else:
                    if not request.client_id:
                        raise MissingClientIdError(request=request)
                    if not self.request_validator.validate_client_id(request.client_id, request):
                        raise InvalidClientIdError(request=request)
                    if alg == 'HS256':
                        key = urlsafe_b64encode(request.app['consumer_secret'].encode()).decode('utf-8').rstrip('=')
                        signature_key = JWK(k=key, kty='oct')
                    elif alg == 'RS256':
                        validate_jws_header(jwstoken, ['RS256'], True)
                        signature_key = self.request_validator.get_signature_key(jwstoken.jose_header[FIELD_KID], request)
                    payload = get_jws_info(jwstoken, signature_key, None, None, None).payload
            except InvalidJWSSignature:
                raise InvalidSignatureError(request=request)
            except JWTException as e:
                raise InvalidRequestFatalError(description=str(e.args[0]), request=request)

            enrich_object(request, payload)

    def validate_duplicate_params(self, request):
        try:
            duplicate_params = request.duplicate_params
            for param in ('request', 'client_id', 'response_type', 'redirect_uri', 'scope', 'state', 'nonce',
                          'acr_values', 'response_mode', 'nonce', 'display', 'prompt', 'claims',
                          'max_age', 'ui_locales', 'id_token_hint', 'login_hint', 'acr_values', 'client_name'):
                if param in duplicate_params:
                    raise InvalidRequestFatalError(description='Duplicate %s parameter.' % param, request=request)
        except ValueError:
            raise InvalidRequestFatalError(description='Unable to parse query string', request=request)

    def _validate_code_challenge(self, request):
        if request.code_challenge_method is not None and request.code_challenge_method not in self.proxy_target._code_challenge_methods.keys():
            raise InvalidParameterValueError('code_challenge_method', 'Unsupported method')
        if request.code_challenge is not None and (len(request.code_challenge) < 43 or len(request.code_challenge) > 128):
            raise InvalidParameterValueError('code_challenge', 'Invalid length (42<size<129)')

    def validate_authorization_request(self, request):
        self.validate_duplicate_params(request)
        self._validate_request_object(request)
        self._validate_code_challenge(request)
        return super().validate_authorization_request(request)

    def _get_state_payload(self, request):
        now = int(time.time())

        state_token = {
            FIELD_JTI: random_token_generator(request),
            FIELD_ISSUER: settings.AGGREGATOR_ISSUER,
            FIELD_AUDIENCE: settings.AGGREGATOR_ISSUER,
            FIELD_ISSUED_TIME: now,
            FIELD_EXPIRATION: now + settings.STATE_TTL,
            FIELD_CLIENT_ID: request.client_id,
            FIELD_ROUTING: request.routing,
            FIELD_REDIRECT_URI: request.redirect_uri
        }

        if request.state:
            state_token[FIELD_STATE] = request.state

        return state_token

    def _get_ip(self):
        request = AggregatorMiddleware.get_current_request()
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR',
                                           request.META.get('HTTP_X_REAL_IP'))
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def create_authentication_response(self, request):
        try:
            _, authentication = self.validate_authorization_request(request)
            request.authentication = authentication

            request.routing = TelcoFinderClient().get_routing_metadata('ipport', self._get_ip())
            if request.routing is None:
                raise AccessDeniedError(description="Unknown user")

            jwt_state_payload = self._get_state_payload(request)
            jwt_state = build_jwe(jwt_state_payload, AggregatorMiddleware.get_correlator(request), settings.JWE_ACCESS_TOKEN_KID)

            params = dict(request.uri_query_params)
            params['state'] = jwt_state
            params['redirect_uri'] = settings.AGGREGATOR_HOST + reverse('aggregator-callback')

            metadata = OidcClient().get_metadata(request.routing[TelcoFinderClient.FIELD_ISSUER])

            redirect_uri = metadata['authorization_endpoint'] + '?' + urlencode(params)

            logger.debug("Redirecting with state", extra={'data': OrderedDict([('state', get_cleaned_data(jwt_state_payload))])})
            logger.info("Redirecting with params", extra={'data': OrderedDict([('params', get_cleaned_data(params))])})
            return {'Location': redirect_uri}, None, 302
        except FatalClientError as e:
            raise
        except OAuth2Error as e:
            request.redirect_uri = request.redirect_uri or self.error_uri
            redirect_uri = common.add_params_to_uri(request.redirect_uri, e.twotuples, fragment=request.response_mode == "fragment")
            return {'Location': redirect_uri}, None, 302

    def _get_code_payload(self, request):
        now = int(time.time())

        code_token = {
            FIELD_JTI: random_token_generator(request),
            FIELD_ISSUER: settings.AGGREGATOR_ISSUER,
            FIELD_AUDIENCE: settings.AGGREGATOR_ISSUER,
            FIELD_ISSUED_TIME: now,
            FIELD_EXPIRATION: now + settings.AUTHORIZATION_CODE_TTL,
            FIELD_CLIENT_ID: request.state_payload[FIELD_CLIENT_ID],
            FIELD_ROUTING: request.state_payload[FIELD_ROUTING],
            FIELD_REDIRECT_URI: request.state_payload[FIELD_REDIRECT_URI],
            FIELD_CODE: request.code
        }

        return code_token

    def create_authorization_code(self, request):
        grant = {'code': build_jwe(self._get_code_payload(request),
                                   AggregatorMiddleware.get_correlator(request), settings.JWE_ACCESS_TOKEN_KID)}
        if FIELD_STATE in request.state_payload:
            grant['state'] = request.state_payload[FIELD_STATE]
        return grant

    def create_callback_response(self, request, token_handler):
        try:
            self.request_validator.validate_callback_response(request)

            if hasattr(request, 'error'):
                request.state = request.state_payload.get(FIELD_STATE, None)
                error_description = getattr(request, 'error_description', None)
                raise CustomOAuth2Error(request.error, description=error_description, request=request)

            grant = self.create_authorization_code(request)
            for modifier in self._code_modifiers:
                grant = modifier(grant, token_handler, request)

            log_metric('ok')
            return self.prepare_authorization_response(request, grant, {}, None, 302)
        except FatalClientError as e:
            raise
        except OAuth2Error as e:
            log_error_metric(e)
            request.redirect_uri = request.redirect_uri or self.error_uri
            redirect_uri = common.add_params_to_uri(request.redirect_uri, e.twotuples, fragment=request.response_mode == "fragment")
            return {'Location': redirect_uri}, None, 302


class AggregatorOAuth2AuthorizationCodeGrant(AggregatorAuthorizationCodeGrantMixin, OAuth2AuthorizationCodeGrant):

    def _get_routing_params(self, request):
        content_type = request.headers.get('Content-Type', None)
        if content_type == 'application/json':
            params = request.body
        else:
            params = dict(parse_qsl(request.body))

        params[FIELD_REDIRECT_URI] = settings.AGGREGATOR_HOST + reverse('aggregator-callback')
        params[FIELD_CODE] = request.auth[FIELD_CODE]

        if hasattr(request, FIELD_CLIENT_ASSERTION):
            client_assertion = deepcopy(getattr(request, FIELD_CLIENT_ASSERTION))
            client_assertion.update({FIELD_AUDIENCE: request.routing[TelcoFinderClient.FIELD_ISSUER]})
            params[FIELD_CLIENT_ASSERTION] = build_jws(client_assertion)

        return params

    def _get_routing_token(self, request):
        request.routing = request.auth[FIELD_ROUTING]

        metadata = OidcClient().get_metadata(request.routing[TelcoFinderClient.FIELD_ISSUER])

        headers = {AggregatorMiddleware.AGGREGATOR_CORRELATOR_HEADER: AggregatorMiddleware.get_correlator(AggregatorMiddleware.get_current_request()),
                   'Content-Type': 'application/x-www-form-urlencoded'}

        response = do_request_call('Routing Token', 'POST', metadata['token_endpoint'],
                                   headers=headers, data=urlencode(self._get_routing_params(request)),
                                   verify=settings.API_SSL_VERIFICATION, timeout=settings.API_HTTP_TIMEOUT)

        if response.status_code == requests.codes.ok:  # @UndefinedVariable
            return response.json()
        else:
            body = response.json()
            raise CustomOAuth2Error(body['error'], status_code=response.status_code, description=body.get('error_description', None))

    def _build_id_token(self, request, id_token):
        jws_token = JWS()
        jws_token.deserialize(id_token)
        jwks_uri = OidcClient().get_data(request.routing[TelcoFinderClient.FIELD_ISSUER], 'jwks_uri')
        signature_key = JWKManager().get_app_public_key(jwks_uri, jws_token.jose_header[FIELD_KID])
        id_token_data = get_jws_info(jws_token, signature_key, request.routing[TelcoFinderClient.FIELD_ISSUER], [request.client_id], None).payload

        id_token_data = {k: v for (k, v) in id_token_data.items() if not k.endswith('_hash')}
        id_token_data[FIELD_ISSUER] = settings.AGGREGATOR_ISSUER
        return build_jws(id_token_data)

    def _generate_token(self, request, token_handler):
        request.token = self._get_routing_token(request)
        request.refresh_token = None
        request.extra_credentials = {"id_token": self._build_id_token(request, request.token["id_token"])} if "id_token" in request.token else {}
        if FIELD_SCOPE in request.token:
            request.scopes = request.token[FIELD_SCOPE].split(' ')
        return request.token

    def create_token_response(self, request, token_handler):
        headers = self._get_default_headers()
        try:
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            logger.debug('Client error during validation of %r. %r.', request, e)
            headers.update(e.headers)
            return headers, e.json, e.status_code

        self._generate_token(request, token_handler)

        #TODO: Refresh token management is not supported yet
        token = token_handler.create_token(request, refresh_token=False)

        for modifier in self._token_modifiers:
            token = modifier(token, token_handler, request)

        self.request_validator.save_token(token, request)
        self.request_validator.invalidate_authorization_code(
            request.client_id, request.code, request)
        headers.update(self._create_cors_headers(request))
        return headers, json.dumps(token), 200


class AggregatorOIDCAuthorizationCodeGrant(AggregatorAuthorizationCodeGrantMixin, AuthorizationCodeGrant):

    def __init__(self, request_validator=None, **kwargs):
        super().__init__(request_validator, **kwargs)
        self.custom_validators.pre_auth.append(validate_mandatory_params)
        self.custom_validators.pre_auth.append(validate_parameter_values)
        self.custom_validators.pre_auth.append(validate_client_name)
        self.custom_validators.post_auth.append(self.complete_information)
        self.custom_validators.post_token.append(self.add_grant)

    def complete_information(self, request):
        return {'acr_values': request.acr_values, 'max_age': request.max_age, 'scopes': request.scopes,
                'client_name': request.client_name, 'grant': request.grant, 'response_mode': request.response_mode}

    def add_grant(self, request):
        if hasattr(request, 'auth') and 'grant' in request.auth:
            request.grant = request.auth['grant']


class AggregatorJWTBearerGrant(oauthlib.oauth2.rfc6749.grant_types.base.GrantTypeBase):

    def validate_token_request(self, request):
        for validator in self.custom_validators.pre_token:
            validator(request)
        # First check duplicate parameters
        required_params = ['grant_type', 'assertion']
        for param in required_params:
            try:
                duplicate_params = request.duplicate_params
            except ValueError:
                raise InvalidRequestFatalError(description='Unable to parse query string.', request=request)
            if param in duplicate_params:
                raise InvalidRequestFatalError(description='Duplicate %s parameter.' % param, request=request)

        for param in required_params:
            if getattr(request, param, None) is None:
                raise MissingParameterError(param, request=request)

        for param, value in [('grant_type', GRANT_TYPE_JWT_BEARER)]:
            if getattr(request, param) != value:
                raise InvalidParameterValueError(param, request=request)

        if not self.request_validator.authenticate_client(request):
            raise InvalidClientError(request=request)
        else:
            if not hasattr(request.client, 'client_id'):
                raise NotImplementedError('Authenticate client must set the request.client.client_id attribute in authenticate_client.', request=request)

        self.validate_grant_type(request)

        for validator in self.custom_validators.post_token:
            validator(request)

    def _get_routing_params(self, request):
        content_type = request.headers.get('Content-Type', None)
        if content_type == 'application/json':
            params = request.body
        else:
            params = dict(parse_qsl(request.body))

        if hasattr(request, FIELD_CLIENT_ASSERTION):
            client_assertion = deepcopy(getattr(request, FIELD_CLIENT_ASSERTION))
            client_assertion.update({FIELD_AUDIENCE: request.routing[TelcoFinderClient.FIELD_ISSUER]})
            params[FIELD_CLIENT_ASSERTION] = build_jws(client_assertion)

        assertion = deepcopy(request.auth)
        assertion.update({
            FIELD_ISSUER: settings.AGGREGATOR_ISSUER if assertion[FIELD_ISSUER] != request.client.client_id else assertion[FIELD_ISSUER],
            FIELD_AUDIENCE: request.routing[TelcoFinderClient.FIELD_ISSUER]
        })
        params[FIELD_ASSERTION] = build_jws(assertion)

        return params

    def _get_routing_token(self, request):
        index = request.auth[FIELD_SUB].find(":")
        request.routing = TelcoFinderClient().get_routing_metadata(request.auth[FIELD_SUB][0:index], request.auth[FIELD_SUB][index+1:])
        if request.routing is None:
            raise InvalidGrantError(description="Unknown sub")

        metadata = OidcClient().get_metadata(request.routing[TelcoFinderClient.FIELD_ISSUER])

        headers = {AggregatorMiddleware.AGGREGATOR_CORRELATOR_HEADER: AggregatorMiddleware.get_correlator(AggregatorMiddleware.get_current_request()),
                   'Content-Type': 'application/x-www-form-urlencoded'}
        response = do_request_call('Routing Token', 'POST', metadata['token_endpoint'],
                                   headers=headers, data=urlencode(self._get_routing_params(request)),
                                   verify=settings.API_SSL_VERIFICATION, timeout=settings.API_HTTP_TIMEOUT)

        if response.status_code == requests.codes.ok:  # @UndefinedVariable
            return response.json()
        else:
            body = response.json()
            raise CustomOAuth2Error(body['error'], status_code=response.status_code, description=body.get('error_description', None))

    def _generate_token(self, request, token_handler):
        request.refresh_token = None
        request.extra_credentials = None
        request.token = self._get_routing_token(request)
        if FIELD_SCOPE in request.token:
            request.scopes = request.token[FIELD_SCOPE].split(' ')
        token = token_handler.create_token(request, refresh_token=False)
        for modifier in self._token_modifiers:
            token = modifier(token, token_handler, request)
        return token

    def create_token_response(self, request, token_handler):
        headers = self._get_default_headers()
        self.validate_token_request(request)
        if self.request_validator.validate_assertion(request):
            token = self._generate_token(request, token_handler)
            self.request_validator.save_token(token, request)
        return headers, json.dumps(token, escape_forward_slashes=False), 200
