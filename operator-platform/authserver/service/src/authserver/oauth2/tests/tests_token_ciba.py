import time
from base64 import b64encode
from copy import deepcopy
from datetime import datetime, timedelta

import requests_mock
from django.conf import settings
from django.test.utils import override_settings
from freezegun.api import freeze_time

from authserver.oauth2.models import ApplicationCollection, UserPcrCollection, TokenCollection
from authserver.oauth2.tests.tests_basic import APPLICATION, USER_PCR, get_signed_jwt, SP_JWT_PRIVATE_KEY
from authserver.oauth2.tests.tests_ciba_authorize import CibaTestCase
from authserver.oauth2.tests.tests_token import TokenTestCase
from authserver.utils.utils import overwrite_dict


class CibaTokenTestCase(TokenTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)
        UserPcrCollection.objects.insert_one(USER_PCR)

    @classmethod
    def get_token_request_parameters(cls, **kwargs):
        params = {
            'auth_req_id': 'abcdefghijklmnnopqrstuvwxyz',
            'grant_type': 'urn:openid:params:grant-type:ciba'
        }
        overwrite_dict(params, kwargs)
        return params

    @classmethod
    def do_ciba_token(cls, authorize_params, token_params, token_headers=None):
        token_headers = token_headers if token_headers is not None else cls.get_default_headers()
        response = CibaTestCase.do_authorize(authorize_params, CibaTestCase.get_default_headers())
        token_params['auth_req_id'] = response.json()['auth_req_id']
        return cls.do_token(token_params, token_headers)

    def _test_token_ok(self, authorize_params, token_params, token_headers):
        response = self.do_ciba_token(authorize_params, token_params, token_headers)
        token, _, id_token_data = self.assertAccessTokenOK(response, refresh_token=True, id_token=True)
        return token, id_token_data

    @classmethod
    def get_db_token(cls, **kwargs):
        now = datetime.utcnow()
        now = now.replace(microsecond=now.microsecond - now.microsecond % 1000)
        token = {
            'access_token': '8eB6GgCzDyFRZKXWpP8AdBQRvdOlO9',
            'scopes': ['openid', 'phone'],
            'access_token_ttl': settings.ACCESS_TOKEN_TTL,
            'expires_at': now + timedelta(seconds=settings.ACCESS_TOKEN_TTL),
            'creation': now,
            'client_id': APPLICATION['_id'],
            'client_name': 'Foo',
            'grant_type': 'urn:openid:params:grant-type:ciba',
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
    def get_jwt_access_token(cls, **kwargs):
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
            'scopes': ['openid', 'phone'],
            'sub': USER_PCR['_id'],
            'uid': USER_PCR['user']
        }
        overwrite_dict(token, kwargs)
        return token

    @classmethod
    def get_id_token(cls, **kwargs):
        now = int(time.time())
        id_token = {
            'acr': '2',
            'amr': ['nbma'],
            'sub': '2128c01f-dcc8-4fde-a74e-eba2f9b1a3af',
            'auth_time': now,
            'iat': now,
            'exp': now + 300,
            'aud': ['68399c5b-3cfa-4348-9f96-33d379077d71'],
            'azp': '68399c5b-3cfa-4348-9f96-33d379077d71',
            'iss': settings.AUTHSERVER_HOST
        }

        overwrite_dict(id_token, kwargs)
        return id_token


class CibaTokenOKTestCase(CibaTokenTestCase):

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_token_ok(self, m):
        CibaTestCase.do_mocking(m)
        authorize_params, _ = CibaTestCase.get_authorize_parameters()
        token, id_token_data = self._test_token_ok(authorize_params, self.get_token_request_parameters(), self.get_default_headers())
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token'], 'refresh_token': token['refresh_token'], 'id_token': token['id_token']}))
        self.assertDictContainsSubset(self.get_id_token(), id_token_data)
        self.assertHash(token['access_token'], id_token_data['at_hash'])
        self.assertDictContainsSubset(self.get_jwt_access_token(), self.get_access_token_data(token['access_token']))

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_no_scope(self, m):
        CibaTestCase.do_mocking(m)
        authorize_params, _ = CibaTestCase.get_authorize_parameters(**{'scope': None})
        token, id_token_data = self._test_token_ok(authorize_params, self.get_token_request_parameters(), self.get_default_headers())
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token'], 'refresh_token': token['refresh_token'], 'id_token': token['id_token'], 'scopes': ['openid', 'phone', 'atp']}))
        self.assertDictContainsSubset(self.get_id_token(), id_token_data)
        self.assertHash(token['access_token'], id_token_data['at_hash'])
        self.assertDictContainsSubset(self.get_jwt_access_token(**{'scopes': ['openid', 'phone', 'atp']}), self.get_access_token_data(token['access_token']))

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_client_secret_post(self, m):
        CibaTestCase.do_mocking(m)

        authorize_params, _ = CibaTestCase.get_authorize_parameters()

        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = APPLICATION['consumer_secret']

        self._test_token_ok(authorize_params, token_params, {})

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_jwt_bearer(self, m):
        CibaTestCase.do_mocking(m)

        authorize_params, _ = CibaTestCase.get_authorize_parameters()

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        self._test_token_ok(authorize_params, token_params, {})


class CibaTokenErrorTestCase(CibaTokenTestCase):

    @requests_mock.mock()
    def test_no_auth(self, m):
        CibaTestCase.do_mocking(m)

        response = self.do_ciba_token(CibaTestCase.get_authorize_parameters()[0], self.get_token_request_parameters(), {})
        self.assertJsonError(response, 401, 'invalid_client')

    @requests_mock.mock()
    def test_client_secret_post_empty_password(self, m):
        CibaTestCase.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        response = self.do_ciba_token(CibaTestCase.get_authorize_parameters()[0], token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    @requests_mock.mock()
    def test_client_secret_post_wrong_client(self, m):
        CibaTestCase.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_id'] = 'wrong'
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_ciba_token(CibaTestCase.get_authorize_parameters()[0], token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    @requests_mock.mock()
    def test_client_secret_post_wrong_password(self, m):
        CibaTestCase.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = 'wrong'
        response = self.do_ciba_token(CibaTestCase.get_authorize_parameters()[0], token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    @requests_mock.mock()
    def test_client_secret_basic_wrong_client(self, m):
        CibaTestCase.do_mocking(m)

        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header('wrong', APPLICATION[ApplicationCollection.FIELD_CONSUMER_SECRET])
        }
        response = self.do_ciba_token(CibaTestCase.get_authorize_parameters()[0], self.get_token_request_parameters(), headers)
        self.assertJsonError(response, 401, 'invalid_client')

    @requests_mock.mock()
    def test_client_secret_basic_wrong_password(self, m):
        CibaTestCase.do_mocking(m)

        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header(APPLICATION[ApplicationCollection.FIELD_ID], 'wrong')
        }
        response = self.do_ciba_token(CibaTestCase.get_authorize_parameters()[0], self.get_token_request_parameters(), headers)
        self.assertJsonError(response, 401, 'invalid_client')

    @requests_mock.mock()
    def test_client_secret_basic_wrong_header(self, m):
        CibaTestCase.do_mocking(m)

        for value in ['foo', 'Basic foo', 'Basic ' + b64encode(f'{APPLICATION["_id"]}'.encode('utf-8')).decode('utf-8')]:
            headers = {'HTTP_AUTHORIZATION': value}
            response = self.do_ciba_token(CibaTestCase.get_authorize_parameters()[0], self.get_token_request_parameters(), headers)
            self.assertJsonError(response, 401, 'invalid_client')

    @requests_mock.mock()
    def test_multiple_auths(self, m):
        CibaTestCase.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_ciba_token(CibaTestCase.get_authorize_parameters()[0], token_params, self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Multiple authentication mechanisms.')

    def test_missing_parameters(self):
        response = self.do_token(self.get_token_request_parameters(**{'auth_req_id': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Missing auth_req_id parameter.')

        response = self.do_token(self.get_token_request_parameters(**{'grant_type': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_grant_type')


class CibaTokenWrongValuesTestCase(CibaTokenTestCase):

    def test_wrong_grant_type(self):
        response = self.do_token(self.get_token_request_parameters(**{'grant_type': 'wrong'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_grant_type')

    @requests_mock.mock()
    def test_wrong_auth_req_id(self, m):
        CibaTestCase.do_mocking(m)

        response = self.do_token(self.get_token_request_parameters(**{'auth_req_id': 'wrong'}),
                                 self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_grant', 'Authorization not found.')

    @requests_mock.mock()
    def test_valid_auth_req_id_with_wrong_client_id(self, m):
        CibaTestCase.do_mocking(m)

        app2 = deepcopy(APPLICATION)
        app2[ApplicationCollection.FIELD_ID] = '19c1afb8-f0ad-42b2-b6c0-cdfcdce051c7'
        app2[ApplicationCollection.FIELD_CONSUMER_SECRET] = 'eeae928b-0385-4090-abbe-7ff193934718'
        ApplicationCollection.objects.insert_one(app2)

        response = CibaTestCase.do_authorize(CibaTestCase.get_authorize_parameters()[0], CibaTestCase.get_default_headers())
        auth_req_id = response.json()['auth_req_id']

        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header(app2[ApplicationCollection.FIELD_ID], app2[ApplicationCollection.FIELD_CONSUMER_SECRET])
        }
        response = self.do_token(self.get_token_request_parameters(**{'auth_req_id': auth_req_id}), headers)
        self.assertJsonError(response, 400, 'invalid_grant', 'Authorization not found.')


@override_settings(ACCESS_TOKEN_TTL=100, REFRESH_TOKEN_TTL=200)
class CibaTTLTestCase(CibaTokenTestCase):

    def do_ttl_token(self):
        token, _ = self._test_token_ok(CibaTestCase.get_authorize_parameters()[0], self.get_token_request_parameters(), self.get_default_headers())
        return token, TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']})

    @requests_mock.mock()
    def test_default_config(self, m):
        CibaTestCase.do_mocking(m)

        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 100)
        self.assertEqual(dbtoken['access_token_ttl'], 100)
        self.assertEqual(dbtoken['refresh_token_ttl'], 200)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 100)
        self.assertEqual(int((dbtoken['refresh_token_expires_at'] - dbtoken['creation']).total_seconds()), 200)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'client_credentials': 202, 'authorization_code': 203, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 204},
                       REFRESH_TOKEN_TTL_BY_GRANT={'client_credentials': 402, 'authorization_code': 403, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 404})
    @requests_mock.mock()
    def test_no_grant_config(self, m):
        CibaTestCase.do_mocking(m)

        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 100)
        self.assertEqual(dbtoken['access_token_ttl'], 100)
        self.assertEqual(dbtoken['refresh_token_ttl'], 200)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 100)
        self.assertEqual(int((dbtoken['refresh_token_expires_at'] - dbtoken['creation']).total_seconds()), 200)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'urn:openid:params:grant-type:ciba': 201, 'client_credentials': 202, 'authorization_code': 203, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 204},
                       REFRESH_TOKEN_TTL_BY_GRANT={'urn:openid:params:grant-type:ciba': 401, 'client_credentials': 402, 'authorization_code': 403, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 404})
    @requests_mock.mock()
    def test_grant_config(self, m):
        CibaTestCase.do_mocking(m)

        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 201)
        self.assertEqual(dbtoken['access_token_ttl'], 201)
        self.assertEqual(dbtoken['refresh_token_ttl'], 401)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 201)
        self.assertEqual(int((dbtoken['refresh_token_expires_at'] - dbtoken['creation']).total_seconds()), 401)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'urn:openid:params:grant-type:ciba': 201},
                       REFRESH_TOKEN_TTL_BY_GRANT={'urn:openid:params:grant-type:ciba': 401})
    @requests_mock.mock()
    def test_client_config(self, m):
        CibaTestCase.do_mocking(m)
        
        ApplicationCollection.objects.update_one(
            {'_id': APPLICATION['_id']},
            {'$set':
                {
                    'grants': [
                        {
                            'grant_type': 'authorization_code',
                            'scopes': [
                                'openid',
                                'phone',
                                'atp'
                            ],
                            'access_token_ttl': 301,
                            'refresh_token_ttl': 501
                        },
                        {
                            'grant_type': 'urn:openid:params:grant-type:ciba',
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

