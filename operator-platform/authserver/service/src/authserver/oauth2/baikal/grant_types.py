import base64
import hashlib
import logging
import time
from base64 import urlsafe_b64encode
from copy import deepcopy

import oauthlib.oauth2.rfc6749.grant_types.base
import ujson as json
from django.conf import settings
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS, InvalidJWSSignature
from oauthlib import common
from oauthlib.oauth2.rfc6749.errors import OAuth2Error, InvalidRequestFatalError, MissingClientIdError, InvalidClientIdError, FatalClientError, InvalidRequestError, \
    InvalidClientError, InvalidScopeError, UnauthorizedClientError
from oauthlib.oauth2.rfc6749.grant_types import AuthorizationCodeGrant as OAuth2AuthorizationCodeGrant
from oauthlib.oauth2.rfc6749.grant_types.base import GrantTypeBase
from oauthlib.openid.connect.core.grant_types import AuthorizationCodeGrant

from authserver.middleware.baikal import log_metric, log_error_metric, BaikalMiddleware
from authserver.oauth2.models import ApplicationCollection, UserPcrCollection
from authserver.utils.exceptions import MissingParameterError, InvalidParameterValueError, InvalidSignatureError, JWTException
from authserver.utils.jws import FIELD_KID, FIELD_ALGORITHM
from authserver.utils.jws import get_jws_info, validate_jws_header
from authserver.utils.schemas import FIELD_ACR_VALUES, FIELD_AUDIENCE, FIELD_ISSUED_TIME
from authserver.utils.utils import enrich_object

logger = logging.getLogger(settings.LOGGING_PREFIX)


RESPONSE_TYPE_CODE = 'code'

GRANT_TYPE_AUTHORIZATION_CODE = 'authorization_code'
GRANT_TYPE_REFRESH_TOKEN = 'refresh_token'
GRANT_TYPE_CLIENT_CREDENTIALS = 'client_credentials'
GRANT_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:grant-type:jwt-bearer'
GRANT_TYPE_CIBA = 'urn:openid:params:grant-type:ciba'


def validate_mandatory_params(request):
    if getattr(request, 'acr_values', None) is None:
        if settings.DEFAULT_ACR_VALUES is None:
            raise MissingParameterError('acr_values', request=request)
        else:
            request.acr_values = ' '.join(settings.DEFAULT_ACR_VALUES)
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


def validate_claims(request):
    return {}


class BaikalAuthorizationCodeGrantMixin:

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

    def _do_authentication(self, authentication, request):
        credentials = deepcopy(authentication)
        # In a real scenario, prompt user for authentication, redirect to an external IdP
        # or resolve origin IP from request to translate it to a user identity
        credentials['uid'] = 'tel:+34618051526'
        # Get subject from identity
        credentials['sub'] = UserPcrCollection.get_pcr_or_create(credentials['uid'], request.app[ApplicationCollection.FIELD_SECTOR_IDENTIFIER])
        # Add authentication data
        credentials['acr'] = request.authentication[FIELD_ACR_VALUES].split(' ')[0]
        credentials['amr'] = ['nbma']
        credentials['claims'] = {}
        credentials['auth_time'] = int(time.time())
        credentials['corr'] = BaikalMiddleware.get_correlator(request)

        enrich_object(request, credentials or {})

    def create_authentication_response(self, request, token_handler):
        try:
            _, authentication = self.validate_authorization_request(request)
            request.authentication = authentication

            self.request_validator.save_authentication(authentication, request)

            # TODO: Authentication
            self._do_authentication(authentication, request)

            grant = self.create_authorization_code(request)
            for modifier in self._code_modifiers:
                grant = modifier(grant, token_handler, request)

            self.request_validator.save_authorization_code(request.client_id, grant, request)
            log_metric('ok')
            return self.prepare_authorization_response(request, grant, {}, None, 302)
        except FatalClientError as e:
            raise
        except OAuth2Error as e:
            return self.get_error_response(request, e)

    def create_callback_response(self, request, token_handler):
        try:
            self.request_validator.validate_callback_response(request)

            grant = self.create_authorization_code(request)
            for modifier in self._code_modifiers:
                grant = modifier(grant, token_handler, request)

            self.request_validator.save_authorization_code(request.client_id, grant, request)
            log_metric('ok')
            return self.prepare_authorization_response(request, grant, {}, None, 302)
        except FatalClientError as e:
            raise
        except OAuth2Error as e:
            return self.get_error_response(request, e)

    def get_error_response(self, request, e):
        log_error_metric(e)
        request.redirect_uri = request.redirect_uri or self.error_uri
        redirect_uri = common.add_params_to_uri(request.redirect_uri, e.twotuples, fragment=request.response_mode == "fragment")
        return {'Location': redirect_uri}, None, 302


class BaikalOAuth2AuthorizationCodeGrant(BaikalAuthorizationCodeGrantMixin, OAuth2AuthorizationCodeGrant):
    pass


class BaikalOIDCAuthorizationCodeGrant(BaikalAuthorizationCodeGrantMixin, AuthorizationCodeGrant):

    def __init__(self, request_validator=None, **kwargs):
        super().__init__(request_validator, **kwargs)
        self.custom_validators.pre_auth.append(validate_mandatory_params)
        self.custom_validators.pre_auth.append(validate_parameter_values)
        self.custom_validators.pre_auth.append(validate_client_name)
        self.custom_validators.post_auth.append(validate_claims)
        self.custom_validators.post_auth.append(self.complete_information)
        self.custom_validators.post_token.append(self.add_grant)

    def complete_information(self, request):
        return {'acr_values': request.acr_values, 'max_age': request.max_age, 'scopes': request.scopes,
                'client_name': request.client_name, 'grant': request.grant, 'response_mode': request.response_mode}

    def add_grant(self, request):
        if hasattr(request, 'auth') and 'grant' in request.auth:
            request.grant = request.auth['grant']


class BaikalCibaGrant(GrantTypeBase):

    def __init__(self, request_validator=None, **kwargs):
        super().__init__(request_validator)
        self.register_token_modifier(self.add_id_token)

    def add_ciba_information(self, token, token_handler, request):
        return self.request_validator.add_ciba_information(token, token_handler, request)

    def id_token_hash(self, value, hashfunc=hashlib.sha256):
        digest = hashfunc(value.encode()).digest()
        left_most = len(digest) // 2
        return base64.urlsafe_b64encode(digest[:left_most]).decode().rstrip("=")

    def add_id_token(self, token, token_handler, request):
        if not request.scopes or 'openid' not in request.scopes:
            return token
        id_token = {
            FIELD_AUDIENCE: request.client_id,
            FIELD_ISSUED_TIME: int(time.time())
        }

        if "access_token" in token:
            id_token["at_hash"] = self.id_token_hash(token["access_token"])

        token['id_token'] = self.request_validator.finalize_id_token(id_token, token, token_handler, request)
        return token

    def create_ciba_authorization_response(self, request, token_handler):
        headers = self._get_default_headers()
        self.request_validator.authenticate_client(request)
        self.validate_authorization_request(request)
        self.request_validator.manage_ciba_authorization_request(request)
        authorization = self.request_validator.save_ciba_authorization_request(request)
        return headers, json.dumps(authorization, escape_forward_slashes=False), 200

    def validate_authorization_request(self, request):
        for param in ('scope', 'login_hint_token', 'acr_values'):
            try:
                duplicate_params = request.duplicate_params
            except ValueError:
                raise InvalidRequestError(description='Unable to parse query string', request=request)
            if param in duplicate_params:
                raise InvalidRequestError(description='Duplicate %s parameter.' % param, request=request)

        if not self.request_validator.validate_client_id(request.client_id, request):
            raise InvalidClientIdError(request=request)

        if not self.request_validator.validate_grant_type(request.client_id, GRANT_TYPE_CIBA, request.app, request):
            raise UnauthorizedClientError(request=request)

        if getattr(request, 'scope', None) is not None:
            request.scopes = request.scope.split(' ')
            if not self.request_validator.validate_scopes(request.client_id, request.scopes, request.app, request):
                raise InvalidScopeError()
        else:
            request.scopes = self.request_validator.get_default_scopes(request.client_id, request)

        if getattr(request, 'id_token_hint', None):
            raise InvalidRequestError('Unsupported hint: id_token_hint')
        elif getattr(request, 'login_hint', None) is not None and getattr(request, 'login_hint_token', None) is not None:
            raise InvalidRequestError('Multiple authorization hint.')
        elif getattr(request, 'login_hint_token', None) is not None:
            self.request_validator.validate_login_hint_token(request)
        elif getattr(request, 'login_hint', None) is not None:
            self.request_validator.validate_login_hint(request)
        else:
            raise InvalidRequestError('Missing hint parameter.')

        return True

    def _generate_token(self, request, token_handler):
        request.refresh_token = None
        request.extra_credentials = None
        token = token_handler.create_token(request, refresh_token=True)
        for modifier in self._token_modifiers:
            token = modifier(token, token_handler, request)
        self.request_validator.save_token(token, request)
        return token

    def create_token_response(self, request, token_handler):
        headers = self._get_default_headers()
        self.validate_token_request(request)
        if self.request_validator.validate_auth_req_id(request):
            token = self._generate_token(request, token_handler)
        return headers, json.dumps(token, escape_forward_slashes=False), 200

    def validate_token_request(self, request):
        for validator in self.custom_validators.pre_token:
            validator(request)
        # First check duplicate parameters
        required_params = ['auth_req_id', 'grant_type']
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

        for param, value in [('grant_type', GRANT_TYPE_CIBA)]:
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


class BaikalJWTBearerGrant(oauthlib.oauth2.rfc6749.grant_types.base.GrantTypeBase):

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

    def _generate_token(self, request, token_handler):
        request.refresh_token = None
        request.extra_credentials = None
        token = token_handler.create_token(request, refresh_token=True)
        for modifier in self._token_modifiers:
            token = modifier(token, token_handler, request)
        self.request_validator.save_token(token, request)
        return token

    def create_token_response(self, request, token_handler):
        headers = self._get_default_headers()
        self.validate_token_request(request)
        if self.request_validator.validate_assertion(request):
            token = self._generate_token(request, token_handler)
        return headers, json.dumps(token, escape_forward_slashes=False), 200
