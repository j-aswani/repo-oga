import logging
import time
from copy import deepcopy
from datetime import timedelta, datetime, timezone
from uuid import uuid4

import ujson as json
from django.conf import settings
from django.core import exceptions
from django.core.validators import URLValidator
from jsonschema.exceptions import ValidationError
from jwcrypto.jws import InvalidJWSSignature, JWS
from jwcrypto.jwt import JWT
from oauthlib.oauth2.rfc6749.errors import OAuth2Error, InvalidScopeError, InvalidRequestFatalError, \
    UnauthorizedClientError, InvalidClientError, InvalidRequestError, InvalidGrantError
from oauthlib.openid import RequestValidator
from pymongo.errors import DuplicateKeyError

from authserver.clients.oidc import OidcClient
from authserver.middleware.baikal import BaikalMiddleware
from authserver.oauth2.baikal.grant_types import GRANT_TYPE_AUTHORIZATION_CODE
from authserver.oauth2.baikal.tokens import refresh_token_expires_in
from authserver.oauth2.models import TokenCollection, CodeCollection, ApplicationCollection, Grant, AuthenticationCollection, JtiCollection, UserPcrCollection, \
    CibaAuthorizationCollection
from authserver.utils.exceptions import InvalidParameterValueError, JWTException, InvalidSignatureError, UnavailableSignatureError, ExpiredLoginHintTokenError, \
    AuthorizationPendingError
from authserver.utils.http import extract_credentials_from_basic_auth
from authserver.utils.jwk import JWKManager
from authserver.utils.jws import validate_jws_header, get_jws_info
from authserver.utils.login_hint import get_login_hint_obj
from authserver.utils.schemas import FIELD_ISSUER, FIELD_KID, FIELD_JTI, JWT_CLIENT_ASSERTION_VALIDATOR, FIELD_SUB, JWT_ASSERTION_VALIDATOR, FIELD_SCOPE, \
    JWT_LOGIN_HINT_TOKEN_VALIDATOR, FIELD_IDENTIFIER, FIELD_IDENTIFIER_TYPE, FIELD_UID
from authserver.utils.utils import to_epoch, remove_tel_prefix

logger = logging.getLogger(settings.LOGGING_PREFIX)

RESPONSE_TYPE_GRANT_MAPPING = {
    'code': GRANT_TYPE_AUTHORIZATION_CODE
}


class BaikalRequestValidator(RequestValidator):

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

    def save_authentication(self, authentication, request):
        del authentication['request']
        authentication[AuthenticationCollection.FIELD_ID] = str(uuid4())
        if AuthenticationCollection.FIELD_PROMPT in authentication and authentication[AuthenticationCollection.FIELD_PROMPT] is not None:
            authentication[AuthenticationCollection.FIELD_PROMPT] = ' '.join(list(authentication[AuthenticationCollection.FIELD_PROMPT])) \
                if authentication[AuthenticationCollection.FIELD_PROMPT] is not None or len(authentication[AuthenticationCollection.FIELD_PROMPT]) > 0 \
                else None
        AuthenticationCollection.update(authentication)

    def save_authorization_code(self, client_id, grant, request, *args, **kwargs):
        code = {
            CodeCollection.FIELD_ID: grant['code'],
            CodeCollection.FIELD_CLIENT_ID: request.client_id,
            CodeCollection.FIELD_CLIENT_NAME: request.client_name,
            CodeCollection.FIELD_UID: request.uid,
            CodeCollection.FIELD_SUB: request.sub,
            CodeCollection.FIELD_ACR: request.acr,
            CodeCollection.FIELD_AMR: request.amr,
            CodeCollection.FIELD_GRANT: request.grant,
            CodeCollection.FIELD_LOGIN_HINT: request.login_hint,
            CodeCollection.FIELD_NONCE: request.nonce,
            CodeCollection.FIELD_REDIRECT_URI: request.redirect_uri,
            CodeCollection.FIELD_SCOPES: request.scopes,
            CodeCollection.FIELD_CLAIMS: request.claims,
            CodeCollection.FIELD_CODE_CHALLENGE: request.code_challenge,
            CodeCollection.FIELD_CODE_CHALLENGE_METHOD: request.code_challenge_method,
            CodeCollection.FIELD_AUTH_TIME: request.auth_time,
            CodeCollection.FIELD_CORRELATOR: BaikalMiddleware.get_correlator(BaikalMiddleware.get_current_request())
        }
        CodeCollection.update(code)
        request.auth = code

    def get_signature_key(self, kid, request):
        if not hasattr(request, 'app') or ApplicationCollection.FIELD_JWKS_URI not in request.app:
            raise UnauthorizedClientError()
        return JWKManager().get_app_public_key(request.app[ApplicationCollection.FIELD_JWKS_URI], kid)

    def authenticate_client(self, request, *args, **kwargs):
        try:
            client_id = request.client_id
            client_secret = request.client_secret

            if [client_secret is not None,
                'Authorization' in request.headers,
                hasattr(request, 'client_assertion_type') or hasattr(request, 'client_assertion')].count(True) > 1:
                raise InvalidRequestFatalError('Multiple authentication mechanisms.')

            if getattr(request, 'client_assertion_type', None) == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' and hasattr(request, 'client_assertion'):
                return self.authenticate_client_assertion(request)
            elif 'Authorization' in request.headers:
                client_id, client_secret = extract_credentials_from_basic_auth(request.headers['Authorization'])

            if client_id is not None and client_secret is not None:
                if self.validate_client_id(client_id, request):
                    return client_secret == request.app[ApplicationCollection.FIELD_CONSUMER_SECRET]
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
                    jwt = get_jws_info(jws_token, signature_key, request.client_id, settings.AUTHSERVER_AUDIENCES, validator=None)
                    self._validate_client_assertion(jwt.payload, request)
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

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        return (redirect_uri is not None or len(redirect_uri) > 0) and redirect_uri == request.auth[CodeCollection.FIELD_REDIRECT_URI]

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        if grant_type == 'refresh_token':
            return True

        request.grants = [deepcopy(grant) for grant in request.app.get(ApplicationCollection.FIELD_GRANTS, []) if grant[Grant.FIELD_GRANT_TYPE] == grant_type]
        return len(request.grants) > 0

    def get_code_challenge_method(self, code, request):
        return request.auth.get(CodeCollection.FIELD_CODE_CHALLENGE_METHOD)

    def get_code_challenge(self, code, request):
        return request.auth.get(CodeCollection.FIELD_CODE_CHALLENGE)

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        request.auth = getattr(request, 'auth', CodeCollection.find_one(code))
        if request.auth is not None:
            BaikalMiddleware.set_correlator(BaikalMiddleware.get_current_request(), request.auth[CodeCollection.FIELD_CORRELATOR])
            return client_id is None or client_id == request.auth[CodeCollection.FIELD_CLIENT_ID]
        return False

    def get_authorization_code_scopes(self, client_id, code, redirect_uri, request):
        if self.validate_code(client_id, code, request.client, request):
            request.scopes = request.auth[CodeCollection.FIELD_SCOPES]
            return request.auth[CodeCollection.FIELD_SCOPES]
        return []

    def save_token(self, token, request, *args, **kwargs):
        now = datetime.utcnow()
        token_data = {
            TokenCollection.FIELD_ACCESS_TOKEN: token['access_token'],
            TokenCollection.FIELD_SCOPES: request.scopes,
            TokenCollection.FIELD_ACCESS_TOKEN_TTL: token['expires_in'],
            TokenCollection.FIELD_ACCESS_TOKEN_EXPIRATION: now + timedelta(seconds=token['expires_in']),
            TokenCollection.FIELD_CREATION: now
        }

        if hasattr(request, 'refresh_token_data'):
            token_data[TokenCollection.FIELD_REFRESH_TOKEN] = token['refresh_token']
            token_data[TokenCollection.FIELD_REFRESH_TOKEN_TTL] = refresh_token_expires_in(request)
            token_data[TokenCollection.FIELD_REFRESH_TOKEN_EXPIRATION] = now + timedelta(seconds=token_data[TokenCollection.FIELD_REFRESH_TOKEN_TTL])
            token_data[TokenCollection.FIELD_EXPIRATION] = max([token_data[TokenCollection.FIELD_ACCESS_TOKEN_EXPIRATION],
                                                                token_data[TokenCollection.FIELD_REFRESH_TOKEN_EXPIRATION]])

            TokenCollection.update(request.refresh_token_data[TokenCollection.FIELD_ID], token_data)
        else:
            token_data[TokenCollection.FIELD_CLIENT_ID] = request.client_id
            token_data[TokenCollection.FIELD_CLIENT_NAME] = getattr(request, 'auth', {}).get(CodeCollection.FIELD_CLIENT_NAME, request.app[ApplicationCollection.FIELD_NAME][0])
            token_data[TokenCollection.FIELD_GRANT_TYPE] = request.grant_type
            token_data[TokenCollection.FIELD_TYPE] = token['token_type']
            if request.grant_type != 'client_credentials':
                token_data[TokenCollection.FIELD_CONSENT_DATE] = datetime.fromtimestamp(
                    request.auth[CodeCollection.FIELD_AUTH_TIME], tz=timezone.utc) if CodeCollection.FIELD_AUTH_TIME in getattr(request, 'auth', {}) else now.replace(microsecond=0)

            if hasattr(request, 'auth'):
                if CodeCollection.FIELD_SUB in request.auth:
                    token_data[TokenCollection.FIELD_SUB] = request.auth[CodeCollection.FIELD_SUB]
                if CodeCollection.FIELD_UID in request.auth:
                    token_data[TokenCollection.FIELD_UID] = request.auth[CodeCollection.FIELD_UID]
                if request.auth.get(CodeCollection.FIELD_CLAIMS, None) is not None:
                    token_data[TokenCollection.FIELD_CLAIMS] = request.auth[CodeCollection.FIELD_CLAIMS]

            if 'id_token' in token:
                token_data[TokenCollection.FIELD_ID_TOKEN] = token['id_token']

            if token.get('refresh_token', None) is not None:
                token_data[TokenCollection.FIELD_REFRESH_TOKEN] = token['refresh_token']
                token_data[TokenCollection.FIELD_REFRESH_TOKEN_TTL] = refresh_token_expires_in(request)
                token_data[TokenCollection.FIELD_REFRESH_TOKEN_EXPIRATION] = now + timedelta(seconds=token_data[TokenCollection.FIELD_REFRESH_TOKEN_TTL])
                token_data[TokenCollection.FIELD_EXPIRATION] = max([token_data[TokenCollection.FIELD_ACCESS_TOKEN_EXPIRATION],
                                                                    token_data[TokenCollection.FIELD_REFRESH_TOKEN_EXPIRATION]])
            else:
                token_data[TokenCollection.FIELD_EXPIRATION] = token_data[TokenCollection.FIELD_ACCESS_TOKEN_EXPIRATION]

            TokenCollection.save(token_data)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        CodeCollection.remove(code)

    def get_authorization_code_nonce(self, client_id, code, redirect_uri, request):
        return request.auth[CodeCollection.FIELD_NONCE]

    def finalize_id_token(self, id_token, token, token_handler, request):
        id_token['iss'] = settings.AUTHSERVER_ISSUER
        id_token['aud'] = [id_token['aud']]
        id_token['azp'] = id_token['aud'][0]
        id_token['sub'] = request.auth[CodeCollection.FIELD_SUB]
        id_token['exp'] = id_token['iat'] + settings.JWT_TTL
        id_token['acr'] = request.auth[CodeCollection.FIELD_ACR]
        id_token['amr'] = request.auth[CodeCollection.FIELD_AMR]
        if request.auth.get(CodeCollection.FIELD_AUTH_TIME, None):
            id_token['auth_time'] = request.auth[CodeCollection.FIELD_AUTH_TIME]

        jwt = JWT(header={'alg': settings.JWT_SIGNING_ALGORITHM, 'kid': JWKManager().get_public_kid()}, claims=id_token)
        jwt.make_signed_token(JWKManager().get_private_key())
        return jwt.serialize(True)

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        refresh_token = TokenCollection.find_one(refresh_token=refresh_token)
        if refresh_token is not None:
            request.refresh_token_data = refresh_token
            request.auth = refresh_token
        return refresh_token is not None

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        return request.refresh_token_data[TokenCollection.FIELD_SCOPES]

    def rotate_refresh_token(self, request):
        return True

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        token = TokenCollection.remove_any(token, request.client_id)
        if token is not None:
            request.auth = token

    def introspect_token(self, token, token_type_hint, request, *args, **kwargs):
        data = TokenCollection.find_one(access_token=token, client_id=request.client_id)
        if data is None:
            data = TokenCollection.find_one(refresh_token=token, client_id=request.client_id)
            if data is None:
                return None
            else:
                exp = data[TokenCollection.FIELD_REFRESH_TOKEN_EXPIRATION]
        else:
            exp = data[TokenCollection.FIELD_ACCESS_TOKEN_EXPIRATION]

        request.auth = data

        claims = {
            'iss': settings.AUTHSERVER_ISSUER,
            'scope': ' '.join(data[TokenCollection.FIELD_SCOPES]),
            'client_id': data[TokenCollection.FIELD_CLIENT_ID],
            'token_type': data[TokenCollection.FIELD_TYPE],
            'aud': [data[TokenCollection.FIELD_CLIENT_ID]],
            'iat': int(to_epoch(data[TokenCollection.FIELD_CREATION])),
            'exp': int(to_epoch(exp))
        }

        if TokenCollection.FIELD_UID in data:
            claims['username'] = data[TokenCollection.FIELD_UID]

        return claims

    def validate_user(self, request, *args, **kwargs):
        return True

    def validate_bearer_token(self, token, scopes, request):
        token = TokenCollection.find_one(token)
        if token is None:
            return False
        request.auth = token
        request.scopes = token[TokenCollection.FIELD_SCOPES]
        return True

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

        # TODO: sub conversion
        if FIELD_SUB in assertion:
            if not assertion[FIELD_SUB].startswith('tel:+'):
                assertion[FIELD_SUB] = 'tel:+34618051526'
            assertion[FIELD_UID] = assertion[FIELD_SUB]
            assertion[FIELD_SUB] = UserPcrCollection.get_pcr_or_create(assertion[FIELD_SUB], request.app[ApplicationCollection.FIELD_SECTOR_IDENTIFIER])

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
                jwt = get_jws_info(jws_token, signature_key, None, settings.AUTHSERVER_AUDIENCES, validator=None)
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

    def manage_ciba_authorization_request(self, request):
        # TODO: Check consents
        return True

    def save_ciba_authorization_request(self, request):
        authorization = {
            'auth_req_id': str(uuid4()),
            'expires_in': settings.CIBA_AUTHORIZATION_TTL,
            'interval': settings.CIBA_AUTHORIZATION_INTERVAL  # only poll mode available
        }

        request.auth = {CibaAuthorizationCollection.FIELD_ID: authorization['auth_req_id'],
                        CibaAuthorizationCollection.FIELD_CLIENT_ID: request.client_id,
                        CibaAuthorizationCollection.FIELD_SCOPES: request.scopes,
                        CibaAuthorizationCollection.FIELD_LOGIN_HINT: request.login_hint,
                        CibaAuthorizationCollection.FIELD_GRANT: request.grant,
                        CibaAuthorizationCollection.FIELD_ACR_VALUES: getattr(request, 'acr_values', None),
                        CibaAuthorizationCollection.FIELD_CORRELATOR: BaikalMiddleware.get_correlator(BaikalMiddleware.get_current_request())}

        # TODO: Mocked -> Authorization
        request.auth.update({
            CibaAuthorizationCollection.FIELD_UID: 'tel:+34618051526' if request.login_hint[FIELD_IDENTIFIER_TYPE] != 'phone_number' else f'tel:{request.login_hint[FIELD_IDENTIFIER]}',
            CibaAuthorizationCollection.FIELD_ACR: '2',
            CibaAuthorizationCollection.FIELD_AMR: ['nbma'],
            CibaAuthorizationCollection.FIELD_AUTH_TIME: int(time.time()),
            CibaAuthorizationCollection.FIELD_STATUS: CibaAuthorizationCollection.STATUS_OK,  # delegated consent
        })

        CibaAuthorizationCollection.update(request.auth)

        return authorization

    def validate_login_hint_token(self, request):
        try:
            try:
                jws_token = JWS()
                jws_token.deserialize(request.login_hint_token)
                validate_jws_header(jws_token, ['RS256'], True)
                login_hint = json.loads(jws_token.objects['payload'].decode('utf-8'))
                JWT_LOGIN_HINT_TOKEN_VALIDATOR.validate(login_hint)
                signature_key = self._get_signature_key_from_issuer(login_hint[FIELD_ISSUER], jws_token.jose_header[FIELD_KID], request)
                jwt = get_jws_info(jws_token, signature_key, None, settings.AUTHSERVER_AUDIENCES, validator=None)

                JtiCollection.insert_jti(request.client_id, jwt.payload[FIELD_JTI],
                                         datetime.fromtimestamp(time.time() + settings.JTI_TTL, timezone.utc))

                request.login_hint = {k: v for k, v in jwt.payload.items() if k in [FIELD_IDENTIFIER, FIELD_IDENTIFIER_TYPE]}

                return True
            except InvalidJWSSignature:
                raise InvalidRequestError(description=f'Invalid login_hint_token ({InvalidSignatureError.description})', request=request)
            except UnavailableSignatureError as e:
                raise InvalidRequestError(description=f'Invalid login_hint_token ({e.description})', request=request)
            except JWTException as e:
                message = str(e.args[0])
                if message == 'Expired JWT':
                    raise ExpiredLoginHintTokenError(request=request)
                raise InvalidRequestError(description=f'Invalid login_hint_token ({message})', request=request)
            except ValidationError as e:
                raise InvalidRequestError(description=f'Invalid login_hint_token ({str(e.args[0])})', request=request)
            except DuplicateKeyError:
                raise InvalidParameterValueError('login_hint_token', message='jti parameter was already used', request=request)
        except OAuth2Error:
            raise
        except Exception as e:
            logger.warning('Error processing login_hint_token jwt: %s', str(e.args[0]))
            raise e

    def validate_login_hint(self, request):
        request.login_hint = get_login_hint_obj(request.login_hint)
        return True

    def validate_auth_req_id(self, request):
        authorization = CibaAuthorizationCollection.find_one(request.client_id, request.auth_req_id)
        if authorization is None:
            raise InvalidGrantError(description='Authorization not found', request=request)

        BaikalMiddleware.set_correlator(BaikalMiddleware.get_current_request(), authorization[CibaAuthorizationCollection.FIELD_CORRELATOR])

        request.auth = authorization
        if authorization[CibaAuthorizationCollection.FIELD_STATUS] == CibaAuthorizationCollection.STATUS_PENDING:
            raise AuthorizationPendingError(request=request)

        CibaAuthorizationCollection.remove(request.auth_req_id)  # Invalidate request

        request.scopes = authorization[CibaAuthorizationCollection.FIELD_SCOPES]
        request.grant = authorization[CibaAuthorizationCollection.FIELD_GRANT]

        request.auth.update(**{
            CodeCollection.FIELD_SUB: UserPcrCollection.get_pcr_or_create(
                authorization[CibaAuthorizationCollection.FIELD_UID], request.app[ApplicationCollection.FIELD_SECTOR_IDENTIFIER])
        })

        return True

    def get_userinfo_claims(self, request):
        claims = {}
        if TokenCollection.FIELD_SUB in request.auth:
            claims[TokenCollection.FIELD_SUB] = request.auth[TokenCollection.FIELD_SUB]
        if TokenCollection.FIELD_UID in request.auth:
            if request.auth[TokenCollection.FIELD_UID].startswith('tel:') and 'phone' in request.auth[TokenCollection.FIELD_SCOPES]:
                claims['phone_number'] = remove_tel_prefix(request.auth[TokenCollection.FIELD_UID])
                claims['phone_number_verified'] = True
        return claims
