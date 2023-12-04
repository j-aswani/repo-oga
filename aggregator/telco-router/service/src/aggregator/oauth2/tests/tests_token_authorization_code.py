import json
import time
from copy import deepcopy
from datetime import datetime

import requests_mock
from django.conf import settings
from django.test.client import Client
from freezegun.api import freeze_time
from jwcrypto.jwt import JWT

from aggregator.devtest_settings import OPERATOR_JWT_KID
from aggregator.oauth2.models import ApplicationCollection
from aggregator.oauth2.tests.tests_authorize import AuthorizationCodeTestCase
from aggregator.oauth2.tests.tests_basic import APPLICATION, get_signed_jwt, SP_JWT_PRIVATE_KEY, OPERATOR_JWT_PRIVATE_KEY
from aggregator.oauth2.tests.tests_token import TokenTestCase
from aggregator.utils.utils import overwrite_dict


class AuthorizationCodeTokenTestCase(TokenTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)

    @classmethod
    def get_token_request_parameters(cls, **kwargs):
        params = {
            'code': 'abcdefghijklmnnopqrstuvwxyz',
            'redirect_uri': APPLICATION['redirect_uri'],
            'grant_type': 'authorization_code'
        }
        overwrite_dict(params, kwargs)
        return params

    @classmethod
    def do_code_token(cls, authorize_params, token_params, headers):
        code = AuthorizationCodeTestCase.do_code(authorize_params)
        token_params['code'] = code
        return cls.do_token(token_params, headers)

    def _test_token_ok(self, authorize_params, token_params, headers):
        response = self.do_code_token(authorize_params, token_params, headers)
        token = self.assertAccessTokenOK(response, refresh_token=False, id_token=True)
        return token

    @classmethod
    def get_operator_id_token(cls, **kwargs):
        now = int(time.time())
        id_token = {
            'acr': '2',
            'amr': ['nbma'],
            'nonce': '70979686-e99a-4dc9-a668-b76c5bbf9ae0',
            'sub': '2128c01f-dcc8-4fde-a74e-eba2f9b1a3af',
            'auth_time': now,
            'iat': now,
            'exp': now + 300,
            'aud': ['68399c5b-3cfa-4348-9f96-33d379077d71'],
            'azp': '68399c5b-3cfa-4348-9f96-33d379077d71',
            'iss': 'http://oauth.operator.com'
        }
        jwt = JWT(header={'alg': settings.JWT_SIGNING_ALGORITHM, 'kid': OPERATOR_JWT_KID}, claims=id_token)
        jwt.make_signed_token(OPERATOR_JWT_PRIVATE_KEY)
        return jwt.serialize(True)

    @classmethod
    def do_mocking(cls, m, jwks_uri_params=None):
        AuthorizationCodeTestCase.do_mocking(m, jwks_uri_params)

        m.post("http://oauth.operator.com/token",
               json={
                   "access_token": "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3",
                   "token_type": "Bearer",
                   "expires_in": 3600,
                   "scope": "phone",
                   "id_token": cls.get_operator_id_token()
               })


class AuthorizationCodeTokenOKTestCase(AuthorizationCodeTokenTestCase):

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_jwt_bearer(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), token_params, {})

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_json_content_type(self, m):
        self.do_mocking(m)

        code = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        token_params = self.get_token_request_parameters()
        token_params['code'] = code
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        client = Client()
        response = client.post('/oauth2/token',
                               data=json.dumps(token_params),
                               content_type='application/json', **{})
        self.assertAccessTokenOK(response, refresh_token=False, id_token=True)


class AuthorizationCodeTokenErrorTestCase(AuthorizationCodeTokenTestCase):

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_token_basic_auth(self, m):
        self.do_mocking(m)

        response = self.do_token(self.get_token_request_parameters(), self.get_default_headers())

        self.assertJsonError(response, 400, 'invalid_request', 'Authentication mechanism is not supported.')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_token_client_secret_post(self, m):
        self.do_mocking(m)

        params = self.get_token_request_parameters()
        params['client_id'] = APPLICATION['_id']
        params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_token(params, {})

        self.assertJsonError(response, 400, 'invalid_request', 'Authentication mechanism is not supported.')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_no_auth(self, m):
        self.do_mocking(m)

        response = self.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), {})
        self.assertJsonError(response, 401, 'invalid_client')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_missing_parameters(self, m):
        self.do_mocking(m)

        code = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'redirect_uri': None,
                                                                      'code': code,
                                                                      'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                                                                      'client_assertion': get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM,
                                                                                                         settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)}),
                                 {})
        self.assertJsonError(response, 400, 'invalid_request', 'Missing redirect URI.')

        AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'code': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', f'Missing code parameter.')

        AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'grant_type': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_grant_type')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_reuse_code(self, m):
        self.do_mocking(m)

        code = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['code'] = code
        for i in range(2):
            token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
            response = self.do_token(token_params, {})
            if i == 0:
                self.assertAccessTokenOK(response, refresh_token=False, id_token=True)
            else:
                self.assertJsonError(response, 400, 'invalid_grant')


class AuthorizationCodeTokenWrongValuesTestCase(AuthorizationCodeTokenTestCase):

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_wrong_grant_type(self, m):
        self.do_mocking(m)

        AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'grant_type': 'wrong'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_grant_type')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_wrong_redirect_uri(self, m):
        self.do_mocking(m)

        code = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'redirect_uri': 'https://www.wrong.com', 'code': code,
                                                                      'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                                                                      'client_assertion': get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM,
                                                                                                         settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)}),
                                 {})
        self.assertJsonError(response, 400, 'invalid_request', 'Mismatching redirect URI.')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_wrong_code(self, m):
        self.do_mocking(m)

        _ = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'code': 'wrong',
                                                                      'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                                                                      'client_assertion': get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM,
                                                                                                         settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)}),
                                 {})
        self.assertJsonError(response, 400, 'invalid_grant')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_valid_code_with_wrong_client_id(self, m):
        self.do_mocking(m)

        app2 = deepcopy(APPLICATION)
        app2[ApplicationCollection.FIELD_ID] = '19c1afb8-f0ad-42b2-b6c0-cdfcdce051c7'
        app2[ApplicationCollection.FIELD_CONSUMER_SECRET] = 'eeae928b-0385-4090-abbe-7ff193934718'
        ApplicationCollection.objects.insert_one(app2)

        code = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())

        response = self.do_token(self.get_token_request_parameters(**{'code': code,
                                                                      'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                                                                      'client_assertion': get_signed_jwt(self.get_default_client_assertion(app2[ApplicationCollection.FIELD_ID]),
                                                                                                         settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)}),
                                 {})
        self.assertJsonError(response, 400, 'invalid_grant')
