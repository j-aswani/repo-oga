import logging
import time
from copy import deepcopy
from datetime import datetime, timezone

import ujson as json
from django.conf import settings
from django.core import exceptions
from django.core.validators import URLValidator
from jsonschema.exceptions import ValidationError
from jwcrypto.jws import InvalidJWSSignature, JWS
from oauthlib.oauth2.rfc6749.errors import OAuth2Error, InvalidScopeError, InvalidRequestFatalError, \
    UnauthorizedClientError, InvalidClientError, InvalidRequestError, InvalidGrantError
from oauthlib.openid import RequestValidator
from pymongo.errors import DuplicateKeyError

from aggregator.clients.oidc import OidcClient
from aggregator.oauth2.models import ApplicationCollection, Grant, JtiCollection
from aggregator.oauth2.telcorouter.grant_types import GRANT_TYPE_AUTHORIZATION_CODE
from aggregator.utils.exceptions import InvalidParameterValueError, JWTException, InvalidSignatureError, UnavailableSignatureError
from aggregator.utils.jwe import get_jwe_info, get_jwe_token
from aggregator.utils.jwk import JWKManager
from aggregator.utils.jws import validate_jws_header, get_jws_info
from aggregator.utils.schemas import FIELD_ISSUER, FIELD_KID, FIELD_JTI, JWT_CLIENT_ASSERTION_VALIDATOR, FIELD_SUB, JWT_ASSERTION_VALIDATOR, FIELD_SCOPE, FIELD_EXPIRATION, \
    JWT_STATE_VALIDATOR, FIELD_REDIRECT_URI, FIELD_CLIENT_ID

logger = logging.getLogger(settings.LOGGING_PREFIX)


RESPONSE_TYPE_GRANT_MAPPING = {
    'code': GRANT_TYPE_AUTHORIZATION_CODE
}


class AggregatorRequestValidator(RequestValidator):

    def validate_client_id(self, client_id, request, *args, **kwargs):
        if hasattr(request, 'app'):
            return True
        if client_id is not None:
            app = ApplicationCollection.find_one_by_id(client_id)
            if app is not None:
                if app[ApplicationCollection.FIELD_STATUS] == ApplicationCollection.FIELD_STATUS_VALUE_ACTIVE:
                    request.app = app
                    request.client_id = client_id
                    request.client = type('', (), {'client_id': client_id})()
                    return True
                logger.warning('Application is inactive')
        return False

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return redirect_uri in request.app.get(ApplicationCollection.FIELD_REDIRECT_URI, [])

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return None

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return self.validate_grant_type(client_id, RESPONSE_TYPE_GRANT_MAPPING.get(response_type, None), client, request)

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        if scopes is None or len(scopes) == 0:
            raise InvalidScopeError(description='No scopes defined.', request=request)

        available_grants = [grant for grant in request.grants if set(scopes).issubset(set(grant[Grant.FIELD_SCOPES]))]
        if len(available_grants) == 0:
            return False

        request.grant = available_grants[0]
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        request.grant = request.grants[0]
        return request.grant.get(Grant.FIELD_SCOPES, [])

    def validate_user_match(self, id_token_hint, scopes, claims, request):
        return True

    def validate_silent_login(self, request):
        return True

    def validate_silent_authorization(self, request):
        return True

    def get_signature_key(self, kid, request):
        if not hasattr(request, 'app') or ApplicationCollection.FIELD_JWKS_URI not in request.app:
            raise UnauthorizedClientError()
        return JWKManager().get_app_public_key(request.app[ApplicationCollection.FIELD_JWKS_URI], kid)

    def authenticate_client(self, request, *args, **kwargs):
        try:
            if [request.client_secret is not None, 'Authorization' in request.headers].count(True) > 0:
                raise InvalidRequestFatalError('Authentication mechanism is not supported.')

            if getattr(request, 'client_assertion_type', None) == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' and hasattr(request, 'client_assertion'):
                return self.authenticate_client_assertion(request)
        except OAuth2Error:
            raise
        except Exception as e:
            logger.warning('Error processing authentication: %s', str(e.args[0]))
        return False

    def authenticate_client_assertion(self, request):
        try:
            try:
                jws_token = JWS()
                jws_token.deserialize(request.client_assertion)
                validate_jws_header(jws_token, ['RS256'], True)
                assertion = json.loads(jws_token.objects['payload'].decode('utf-8'))
                JWT_CLIENT_ASSERTION_VALIDATOR.validate(assertion)
                iss = assertion.get(FIELD_ISSUER, None)
                if (request.client_id is None or request.client_id == iss) and self.validate_client_id(iss, request):
                    signature_key = self.get_signature_key(jws_token.jose_header[FIELD_KID], request)
                    jwt = get_jws_info(jws_token, signature_key, request.client_id, settings.AGGREGATOR_AUDIENCES, validator=None)
                    self._validate_client_assertion(jwt.payload, request)
                    request.client_assertion = jwt.payload
                    return True
            except InvalidJWSSignature:
                raise InvalidClientError(description=InvalidSignatureError.description, request=request)
            except UnavailableSignatureError as e:
                raise InvalidClientError(description=e.description, request=request)
            except JWTException as e:
                raise InvalidRequestError(description=str(e.args[0]), request=request)
        except OAuth2Error:
            raise
        except Exception as e:
            logger.warning('Error processing client assertion: %s', str(e.args[0]))
            pass
        return False

    def _validate_client_assertion(self, assertion, request):
        if assertion[FIELD_SUB] != assertion[FIELD_ISSUER]:
            raise InvalidParameterValueError('client_assertion', message='sub parameter does not match with issuer', request=request)
        try:
            JtiCollection.insert_jti(request.client_id, assertion[FIELD_JTI],
                                     datetime.fromtimestamp(time.time() + settings.JTI_TTL, timezone.utc))
        except DuplicateKeyError:
            raise InvalidParameterValueError('client_assertion', message='jti parameter was already used', request=request)

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        return True

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        if grant_type == 'refresh_token':
            return True

        request.grants = [deepcopy(grant) for grant in request.app.get(ApplicationCollection.FIELD_GRANTS, []) if grant[Grant.FIELD_GRANT_TYPE] == grant_type]
        return len(request.grants) > 0

    def validate_callback_response(self, request):

        if request.state is None:
            raise InvalidRequestFatalError('Missing state parameter.', request=request)

        try:
            request.state_payload = get_jwe_info(get_jwe_token(request.state), settings.AGGREGATOR_ISSUER, JWT_STATE_VALIDATOR).payload
            request.redirect_uri = request.state_payload[FIELD_REDIRECT_URI]
        except InvalidJWSSignature:
            raise InvalidRequestFatalError('Invalid JWT state.', request=request)
        except JWTException as e:
            raise InvalidRequestFatalError(str(e.args[0]), request=request)

        return True

    def save_token(self, token, request, *args, **kwargs):
        return

    def validate_user(self, request, *args, **kwargs):
        return True

    def _get_code_payload(self, code):
        try:
            jwe_token = get_jwe_token(code)
            token = get_jwe_info(jwe_token, settings.AGGREGATOR_ISSUER, None)
            return token.payload
        except Exception as e:
            logger.warning('Error validating code: %s', str(e.args[0]))
            return None

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        request.auth = getattr(request, 'auth', self._get_code_payload(code))
        if request.auth is not None:
            jti = JtiCollection.find_jti(client_id, request.auth[FIELD_JTI])
            return (client_id is None or client_id == request.auth[FIELD_CLIENT_ID]) \
                and request.auth[FIELD_EXPIRATION] > int(time.time()) \
                and jti is None
        return False

    def get_authorization_code_scopes(self, client_id, code, redirect_uri, request):
        return []

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        return (redirect_uri is not None or len(redirect_uri) > 0) and redirect_uri == request.auth[FIELD_REDIRECT_URI]

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        JtiCollection.insert_jti(client_id, request.auth[FIELD_JTI], datetime.fromtimestamp(request.auth[FIELD_EXPIRATION]))

    def validate_bearer_token(self, token, scopes, request):
        try:
            jwe_token = get_jwe_token(token)
            token = get_jwe_info(jwe_token, settings.AGGREGATOR_ISSUER, None)
            request.token = token.payload
            return request.token[FIELD_EXPIRATION] > int(time.time())
        except Exception as e:
            logger.warning('Error validating token: %s', str(e.args[0]))
            return False

    def _validate_assertion_payload(self, assertion, request):
        if FIELD_SCOPE in assertion:
            request.scopes = assertion[FIELD_SCOPE].split(' ')
            if not self.validate_scopes(request.client_id, request.scopes, request.app, request):
                raise InvalidScopeError()
        else:
            request.scopes = self.get_default_scopes(request.client_id, request)

        try:
            JtiCollection.insert_jti(request.client_id, assertion[FIELD_JTI], datetime.fromtimestamp(time.time() + settings.JTI_TTL, timezone.utc))
        except DuplicateKeyError:
            raise InvalidGrantError('jti parameter was already used')

    def _get_signature_key_from_issuer(self, issuer, kid, request):
        try:
            # URL Issuer 
            URLValidator()(issuer)
            jwks_uri = OidcClient().get_data(issuer, 'jwks_uri')
            return JWKManager().get_app_public_key(jwks_uri, kid)
        except exceptions.ValidationError:
            # Client Id Issuer
            if request.app[ApplicationCollection.FIELD_ID] != issuer:
                raise JWTException('Invalid issuer')
            return self.get_signature_key(kid, request)

    def validate_assertion(self, request):
        try:
            try:
                jws_token = JWS()
                jws_token.deserialize(request.assertion)
                validate_jws_header(jws_token, ['RS256'], True)
                assertion = json.loads(jws_token.objects['payload'].decode('utf-8'))
                JWT_ASSERTION_VALIDATOR.validate(assertion)
                signature_key = self._get_signature_key_from_issuer(assertion[FIELD_ISSUER], jws_token.jose_header[FIELD_KID], request)
                jwt = get_jws_info(jws_token, signature_key, None, settings.AGGREGATOR_AUDIENCES, validator=None)
                request.auth = jwt.payload
                self._validate_assertion_payload(jwt.payload, request)
                return True
            except InvalidJWSSignature:
                raise InvalidGrantError(description=InvalidSignatureError.description, request=request)
            except UnavailableSignatureError as e:
                raise InvalidGrantError(description=e.description, request=request)
            except JWTException as e:
                raise InvalidGrantError(description=str(e.args[0]), request=request)
            except ValidationError as e:
                raise InvalidGrantError(description=str(e.args[0]), request=request)
        except OAuth2Error:
            raise
        except Exception as e:
            logger.warning('Error processing jwt assertion: %s', str(e.args[0]))
            raise e
