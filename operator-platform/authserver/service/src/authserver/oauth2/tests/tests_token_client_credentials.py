import json
import time
from base64 import b64encode
from datetime import datetime
from datetime import timedelta

import requests_mock
from django.conf import settings
from django.test.client import Client
from django.test.utils import override_settings
from freezegun.api import freeze_time

from authserver.oauth2.models import ApplicationCollection, TokenCollection
from authserver.oauth2.tests.tests_basic import APPLICATION, get_signed_jwt, SP_JWT_PRIVATE_KEY
from authserver.oauth2.tests.tests_token import TokenTestCase
from authserver.utils.utils import overwrite_dict


class ClientCredentialsTokenTestCase(TokenTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)

    @classmethod
    def get_token_request_parameters(cls, **kwargs):

        params = {
            'scope': 'question',
            'grant_type': 'client_credentials'
        }

        overwrite_dict(params, kwargs)

        return params

    @classmethod
    def get_db_token(cls, **kwargs):
        now = datetime.utcnow()
        now = now.replace(microsecond=now.microsecond - now.microsecond % 1000)
        token = {
            'access_token': '8eB6GgCzDyFRZKXWpP8AdBQRvdOlO9',
            'scopes': ['question'],
            'access_token_ttl': settings.ACCESS_TOKEN_TTL,
            'expires_at': now + timedelta(seconds=settings.ACCESS_TOKEN_TTL),
            'creation': now,
            'client_id': APPLICATION['_id'],
            'client_name': 'Foo',
            'grant_type': 'client_credentials',
            'type': 'Bearer',
            'expiration': now + timedelta(seconds=settings.ACCESS_TOKEN_TTL)
        }

        overwrite_dict(token, kwargs)

        return token

    @classmethod
    def get_jwt_access_token(self, **kwargs):
        now = time.time()
        token = {
            'aud': [APPLICATION['_id']],
            'client_id': '68399c5b-3cfa-4348-9f96-33d379077d71',
            'exp': int(now) + 600,
            'iat': int(now),
            'iss': settings.AUTHSERVER_HOST,
            'scopes': ['question']
        }

        overwrite_dict(token, kwargs)

        return token


class ClientCredentialsTokenOKTestCase(ClientCredentialsTokenTestCase):

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_token_ok(self):
        response = self.do_token(self.get_token_request_parameters(), self.get_default_headers())
        token, _, _ = self.assertAccessTokenOK(response, refresh_token=False, id_token=False)
        self.assertNotIn('refresh_token', token)
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token']}))
        self.assertDictContainsSubset(self.get_jwt_access_token(), self.get_access_token_data(token['access_token']))
        return token, dbtoken

    def test_authorization_no_padding(self):
        headers = self.get_default_headers()
        headers['HTTP_AUTHORIZATION'] = headers['HTTP_AUTHORIZATION'].rstrip('=')
        response = self.do_token(self.get_token_request_parameters(), headers)
        self.assertAccessTokenOK(response, refresh_token=False, id_token=False)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_token_no_scope(self):
        params = self.get_token_request_parameters(**{'scope': None})
        response = self.do_token(params, self.get_default_headers())
        token, _, _ = self.assertAccessTokenOK(response, refresh_token=False, id_token=False)
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token'], 'scopes': ['question', 'atp']}))
        self.assertDictContainsSubset(self.get_jwt_access_token(**{'scopes': ['question', 'atp']}), self.get_access_token_data(token['access_token']))

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_token_ok_client_secret_post(self):
        params = self.get_token_request_parameters()
        params['client_id'] = APPLICATION['_id']
        params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_token(params, {})

        token, _, _ = self.assertAccessTokenOK(response, refresh_token=False, id_token=False)
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token']}))

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_jwt_bearer(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})
        token, _, _ = self.assertAccessTokenOK(response, refresh_token=False, id_token=False)
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token']}))

    def test_json_content_type(self):
        client = Client()
        response = client.post('/oauth2/token',
                               data=json.dumps(self.get_token_request_parameters()),
                               content_type='application/json', **self.get_default_headers())
        self.assertAccessTokenOK(response, refresh_token=False, id_token=False)


class ClientCredentialsTokenErrorTestCase(ClientCredentialsTokenTestCase):

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
        response = self.do_token(self.get_token_request_parameters(**{'grant_type': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_grant_type')

    def test_invalid_grant(self):
        ApplicationCollection.objects.update_one(
            {'_id': APPLICATION['_id']},
            {
                '$set': {
                    'grants': [
                        {
                            'grant_type': 'urn:openid:params:grant-type:ciba',
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


class ClientCredentialsTokenWrongValuesTestCase(ClientCredentialsTokenTestCase):

    def test_wrong_scope(self):
        response = self.do_token(self.get_token_request_parameters(**{'scope': 'wrong'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_scope', None)

    def test_wrong_grant_type(self):
        response = self.do_token(self.get_token_request_parameters(**{'grant_type': 'wrong'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_grant_type')


@override_settings(ACCESS_TOKEN_TTL=100, REFRESH_TOKEN_TTL=200)
class ClientCredentialsTTLTestCase(ClientCredentialsTokenTestCase):

    def do_ttl_token(self):
        response = self.do_token(self.get_token_request_parameters(), self.get_default_headers())
        token, _, _ = self.assertAccessTokenOK(response, refresh_token=False, id_token=False)
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token']})
        return token, dbtoken

    def test_default_config(self):
        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 100)
        self.assertEqual(dbtoken['access_token_ttl'], 100)
        self.assertNotIn('refresh_token_ttl', dbtoken)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 100)
        self.assertNotIn('refresh_token_expires_at', dbtoken)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'authorization_code': 202, 'urn:openid:params:grant-type:ciba': 203, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 204},
                       REFRESH_TOKEN_TTL_BY_GRANT={'authorization_code': 402, 'urn:openid:params:grant-type:ciba': 403, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 404})
    def test_no_grant_config(self):
        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 100)
        self.assertEqual(dbtoken['access_token_ttl'], 100)
        self.assertNotIn('refresh_token_ttl', dbtoken)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 100)
        self.assertNotIn('refresh_token_expires_at', dbtoken)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'authorization_code': 201, 'client_credentials': 202, 'urn:openid:params:grant-type:ciba': 203, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 204})
    def test_grant_config(self):
        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 202)
        self.assertEqual(dbtoken['access_token_ttl'], 202)
        self.assertNotIn('refresh_token_ttl', dbtoken)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 202)
        self.assertNotIn('refresh_token_expires_at', dbtoken)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'client_credentials': 201},
                       REFRESH_TOKEN_TTL_BY_GRANT={'client_credentials': 401})
    def test_client_config(self):
        ApplicationCollection.objects.update_one(
            {'_id': APPLICATION['_id']},
            {
                '$set': {
                    'grants': [
                        {
                            'grant_type': 'client_credentials',
                            'scopes': [
                                'question'
                            ],
                            'access_token_ttl': 300
                        },
                        {
                            'grant_type': 'authorization_code',
                            'scopes': [
                                'openid',
                                'phone',
                                'atp'
                            ],
                            'access_token_ttl': 301,
                            'refresh_token_ttl': 501
                        }
                    ]
                }
            }
        )
        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 300)
        self.assertEqual(dbtoken['access_token_ttl'], 300)
        self.assertNotIn('refresh_token_ttl', dbtoken)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 300)
        self.assertNotIn('refresh_token_expires_at', dbtoken)
