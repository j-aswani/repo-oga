import time
from base64 import b64encode
from datetime import datetime
from datetime import timedelta
from uuid import uuid4

import requests_mock
from django.conf import settings
from django.test.utils import override_settings
from freezegun.api import freeze_time

from authserver.oauth2.models import ApplicationCollection, TokenCollection, UserPcrCollection
from authserver.oauth2.tests.tests_basic import APPLICATION, get_signed_jwt, SP_JWT_PRIVATE_KEY, USER_PCR
from authserver.oauth2.tests.tests_token import TokenTestCase
from authserver.utils.utils import overwrite_dict


class JwtBearerTokenTestCase(TokenTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)
        UserPcrCollection.objects.insert_one(USER_PCR)

    @classmethod
    def get_default_assertion(cls, **kwargs):
        now = time.time()

        assertion = {
            'iss': APPLICATION['_id'],
            'aud': f'{settings.AUTHSERVER_HOST}',
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

    @classmethod
    def get_db_token(cls, **kwargs):
        now = datetime.utcnow()
        now = now.replace(microsecond=now.microsecond - now.microsecond % 1000)
        token = {
            'access_token': '8eB6GgCzDyFRZKXWpP8AdBQRvdOlO9',
            'scopes': ['phone'],
            'access_token_ttl': settings.ACCESS_TOKEN_TTL,
            'expires_at': now + timedelta(seconds=settings.ACCESS_TOKEN_TTL),
            'creation': now,
            'client_id': APPLICATION['_id'],
            'client_name': 'Foo',
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'consent_date': now.replace(microsecond=0),
            'sub': '2128c01f-dcc8-4fde-a74e-eba2f9b1a3af',
            'uid': 'tel:+34618051526',
            'type': 'Bearer',
            'refresh_token': 'dNKEPRR4j3CFpwSFOslmzODFjY9XaH',
            'refresh_token_ttl': settings.REFRESH_TOKEN_TTL,
            'refresh_token_expires_at': now + timedelta(seconds=settings.REFRESH_TOKEN_TTL),
            'expiration': max([now + timedelta(seconds=settings.REFRESH_TOKEN_TTL), now + timedelta(seconds=settings.ACCESS_TOKEN_TTL)])
        }

        overwrite_dict(token, kwargs)
        return token

    @classmethod
    def get_jwt_access_token(self, **kwargs):
        now = time.time()
        token = {
            'acr': '2',
            'amr': ['nbma'],
            'aud': [APPLICATION['_id']],
            'auth_time': int(now),
            'client_id': '68399c5b-3cfa-4348-9f96-33d379077d71',
            'exp': int(now) + 600,
            'iat': int(now),
            'iss': settings.AUTHSERVER_HOST,
            'scopes': ['phone'],
            'sub': USER_PCR['_id'],
            'uid': USER_PCR['user']
        }
        overwrite_dict(token, kwargs)
        return token


class JwtBearerTokenOKTestCase(JwtBearerTokenTestCase):

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_token_ok(self, m):
        self.do_mocking(m)

        response = self.do_token(self.get_token_request_parameters(), self.get_default_headers())
        token, _, _ = self.assertAccessTokenOK(response, refresh_token=True, id_token=False)
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token'], 'refresh_token': token['refresh_token']}))
        self.assertDictContainsSubset(self.get_jwt_access_token(), self.get_access_token_data(token['access_token']))
        return token, dbtoken

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_token_ok_client_secret_post(self, m):
        self.do_mocking(m)

        params = self.get_token_request_parameters()
        params['client_id'] = APPLICATION['_id']
        params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_token(params, {})

        token, _, _ = self.assertAccessTokenOK(response, refresh_token=True, id_token=False)
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token'], 'refresh_token': token['refresh_token']}))

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_jwt_bearer(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})
        token, _, _ = self.assertAccessTokenOK(response, refresh_token=True, id_token=False)
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token'], 'refresh_token': token['refresh_token']}))

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_no_scope(self, m):
        self.do_mocking(m)
        response = self.do_token(self.get_token_request_parameters(**{'scope': None}), self.get_default_headers())
        token, _, _ = self.assertAccessTokenOK(response, refresh_token=True, id_token=False)
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token'], 'refresh_token': token['refresh_token'], 'scopes': ['openid', 'phone', 'atp']}))
        self.assertDictContainsSubset(self.get_jwt_access_token(**{'scopes': ['openid', 'phone', 'atp']}), self.get_access_token_data(token['access_token']))


class JwtBearerTokenErrorTestCase(JwtBearerTokenTestCase):

    def test_no_auth(self):
        response = self.do_token(self.get_token_request_parameters(), {})
        self.assertJsonError(response, 401, 'invalid_client', None)

    def test_client_secret_post_empty_password(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        response = self.do_token(token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_wrong_client(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = 'wrong'
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_token(token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_wrong_password(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = 'wrong'
        response = self.do_token(token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_client(self):
        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header('wrong', APPLICATION[ApplicationCollection.FIELD_CONSUMER_SECRET])
        }
        response = self.do_token(self.get_token_request_parameters(), headers)
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_password(self):
        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header(APPLICATION[ApplicationCollection.FIELD_ID], 'wrong')
        }
        response = self.do_token(self.get_token_request_parameters(), headers)
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_header(self):
        for value in ['foo', 'Basic foo', 'Basic ' + b64encode(f'{APPLICATION["_id"]}'.encode('utf-8')).decode('utf-8')]:
            headers = {'HTTP_AUTHORIZATION': value}
            response = self.do_token(self.get_token_request_parameters(), headers)
            self.assertJsonError(response, 401, 'invalid_client')

    @requests_mock.mock()
    def test_multiple_auths(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_token(token_params, self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Multiple authentication mechanisms.')

    def test_missing_parameters(self):
        response = self.do_token(self.get_token_request_parameters(**{'assertion': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Missing assertion parameter.')

        response = self.do_token(self.get_token_request_parameters(**{'grant_type': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_grant_type')

    def test_invalid_grant(self):
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
        response = self.do_token(self.get_token_request_parameters(), self.get_default_headers())
        self.assertJsonError(response, 400, 'unauthorized_client')


class JwtBearerTokenWrongValuesTestCase(JwtBearerTokenTestCase):

    @requests_mock.mock()
    def test_wrong_scope(self, m):
        self.do_mocking(m)

        response = self.do_token(self.get_token_request_parameters(**{'scope': 'wrong'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_scope', None)

    @requests_mock.mock()
    def test_wrong_grant_type(self, m):
        self.do_mocking(m)

        response = self.do_token(self.get_token_request_parameters(**{'grant_type': 'wrong'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_grant_type')


@override_settings(ACCESS_TOKEN_TTL=100, REFRESH_TOKEN_TTL=200)
class JwtBearerTokenTTLTestCase(JwtBearerTokenTestCase):

    def do_ttl_token(self):
        response = self.do_token(self.get_token_request_parameters(), self.get_default_headers())
        token, _, _ = self.assertAccessTokenOK(response, refresh_token=True, id_token=False)
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token']})
        return token, dbtoken

    @requests_mock.mock()
    def test_default_config(self, m):
        self.do_mocking(m)

        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 100)
        self.assertEqual(dbtoken['access_token_ttl'], 100)
        self.assertEqual(dbtoken['refresh_token_ttl'], 200)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 100)
        self.assertEqual(int((dbtoken['refresh_token_expires_at'] - dbtoken['creation']).total_seconds()), 200)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'client_credentials': 202, 'authorization_code': 203, 'urn:openid:params:grant-type:ciba': 204},
                       REFRESH_TOKEN_TTL_BY_GRANT={'client_credentials': 402, 'authorization_code': 403, 'urn:openid:params:grant-type:ciba': 404})
    @requests_mock.mock()
    def test_no_grant_config(self, m):
        self.do_mocking(m)

        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 100)
        self.assertEqual(dbtoken['access_token_ttl'], 100)
        self.assertEqual(dbtoken['refresh_token_ttl'], 200)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 100)
        self.assertEqual(int((dbtoken['refresh_token_expires_at'] - dbtoken['creation']).total_seconds()), 200)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'urn:ietf:params:oauth:grant-type:jwt-bearer': 201, 'client_credentials': 202, 'authorization_code': 203, 'urn:openid:params:grant-type:ciba': 204},
                       REFRESH_TOKEN_TTL_BY_GRANT={'urn:ietf:params:oauth:grant-type:jwt-bearer': 401, 'client_credentials': 402, 'authorization_code': 403, 'urn:openid:params:grant-type:ciba': 404})
    @requests_mock.mock()
    def test_grant_config(self, m):
        self.do_mocking(m)

        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 201)
        self.assertEqual(dbtoken['access_token_ttl'], 201)
        self.assertEqual(dbtoken['refresh_token_ttl'], 401)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 201)
        self.assertEqual(int((dbtoken['refresh_token_expires_at'] - dbtoken['creation']).total_seconds()), 401)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'urn:ietf:params:oauth:grant-type:jwt-bearer': 201},
                       REFRESH_TOKEN_TTL_BY_GRANT={'urn:ietf:params:oauth:grant-type:jwt-bearer': 401})
    @requests_mock.mock()
    def test_client_config(self, m):
        self.do_mocking(m)

        ApplicationCollection.objects.update_one(
            {'_id': APPLICATION['_id']},
            {
                '$set': {
                    'grants': [
                        {
                            'grant_type': 'urn:openid:params:grant-type:ciba',
                            'scopes': [
                                'openid',
                                'phone',
                                'atp'
                            ],
                            'access_token_ttl': 301,
                            'refresh_token_ttl': 501
                        },
                        {
                            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                            'scopes': [
                                'openid',
                                'phone',
                                'atp'
                            ],
                            'access_token_ttl': 300,
                            'refresh_token_ttl': 500
                        }
                    ]
                }
            }
        )
        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 300)
        self.assertEqual(dbtoken['access_token_ttl'], 300)
        self.assertEqual(dbtoken['refresh_token_ttl'], 500)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 300)
        self.assertEqual(int((dbtoken['refresh_token_expires_at'] - dbtoken['creation']).total_seconds()), 500)
