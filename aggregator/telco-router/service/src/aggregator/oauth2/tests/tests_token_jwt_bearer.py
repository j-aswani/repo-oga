import time
from datetime import datetime
from uuid import uuid4

import requests_mock
from django.conf import settings
from freezegun.api import freeze_time
from jwcrypto import jwe

from aggregator.oauth2.models import ApplicationCollection
from aggregator.oauth2.tests.tests_basic import APPLICATION, get_signed_jwt, SP_JWT_PRIVATE_KEY, USER_PCR
from aggregator.oauth2.tests.tests_token import TokenTestCase
from aggregator.utils.jwe import get_jwe_info
from aggregator.utils.utils import overwrite_dict


class JwtBearerTokenTestCase(TokenTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)

    @classmethod
    def do_mocking(cls, m, jwks_uri_params=None):
        super().do_mocking(m, jwks_uri_params)

        m.post("http://oauth.operator.com/token",
              json={
                  "access_token": "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3",
                  "token_type": "Bearer",
                  "expires_in": 3600,
                  "scope": "phone"
              })

    @classmethod
    def get_default_assertion(cls, **kwargs):
        now = time.time()

        assertion = {
            'iss': APPLICATION['_id'],
            'aud': settings.AGGREGATOR_HOST,
            'jti': str(uuid4()),
            'iat': int(now),
            'exp': int(now) + 300,
            "sub": USER_PCR['user'],
            "scope": "phone",
            "acr": "2",
            "amr": ["nbma"],
            "auth_time": int(now)
        }

        overwrite_dict(assertion, kwargs)

        return assertion

    @classmethod
    def get_token_request_parameters(cls, **kwargs):

        params = {
            'scope': 'phone',
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': get_signed_jwt(cls.get_default_assertion(**kwargs), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        }

        overwrite_dict(params, kwargs)

        return params


class JwtBearerTokenOKTestCase(JwtBearerTokenTestCase):

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_jwt_bearer(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})
        token = self.assertAccessTokenOK(response, refresh_token=False, id_token=False)

        jwe_token = jwe.JWE()
        jwe_token.deserialize(token['access_token'])
        aggregator_internal_token = get_jwe_info(jwe_token, None, None)
        self.assertEqual(aggregator_internal_token.payload['access_token'], "MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3")
        self.assertEqual(aggregator_internal_token.payload['exp'], int(time.time()) + 3600)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_no_scope(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters(**{'scope': None})
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})

        token = self.assertAccessTokenOK(response, refresh_token=False, id_token=False)


class JwtBearerTokenErrorTestCase(JwtBearerTokenTestCase):

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

    def test_no_auth(self):
        response = self.do_token(self.get_token_request_parameters(), {})
        self.assertJsonError(response, 401, 'invalid_client', None)

    def test_missing_parameters(self):
        token_params = self.get_token_request_parameters(**{'assertion': None})
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})
        self.assertJsonError(response, 400, 'invalid_request', 'Missing assertion parameter.')

        token_params = self.get_token_request_parameters(**{'grant_type': None})
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})
        self.assertJsonError(response, 400, 'unsupported_grant_type')

    @requests_mock.mock()
    def test_invalid_grant(self, m):
        self.do_mocking(m)

        ApplicationCollection.objects.update_one(
            {'_id': APPLICATION['_id']},
            {
                '$set': {
                    'grants': [
                        {
                            'grant_type': 'client_credentials',
                            'scopes': [
                                'openid',
                                'atp'
                            ]
                        }
                    ]
                }
            }
        )
        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})
        self.assertJsonError(response, 400, 'unauthorized_client')

    @requests_mock.mock()
    def test_authserver_error(self, m):
        self.do_mocking(m)

        m.post("http://oauth.operator.com/token",
               status_code=401,
               json={
                   "error": "invalid_client",
                   "error_description": "Unknown client"
               })

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})
        self.assertJsonError(response, 401, 'invalid_client', "Unknown client.")

    @requests_mock.mock()
    def test_telcofinder_unknown_error(self, m):
        self.do_mocking(m)

        m.get('http://api.aggregator.com/.well-known/webfinger', status_code=404)

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})
        self.assertJsonError(response, 400, 'invalid_grant', "Unknown sub.")


class JwtBearerTokenWrongValuesTestCase(JwtBearerTokenTestCase):

    @requests_mock.mock()
    def test_wrong_scope(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters(**{'scope': 'wrong'})
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})

        self.assertJsonError(response, 400, 'invalid_scope', None)

    @requests_mock.mock()
    def test_wrong_grant_type(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters(**{'grant_type': 'wrong'})
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})

        self.assertJsonError(response, 400, 'unsupported_grant_type')

