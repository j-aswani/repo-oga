
import json
from datetime import datetime

import requests_mock
from django.conf import settings
from django.test.client import Client
from freezegun.api import freeze_time

from authserver.oauth2.models import ApplicationCollection, TokenCollection
from authserver.oauth2.tests.tests_authorize import AuthorizationCodeTestCase
from authserver.oauth2.tests.tests_basic import APPLICATION, get_signed_jwt, SP_JWT_PRIVATE_KEY
from authserver.oauth2.tests.tests_token import TokenTestCase
from authserver.oauth2.tests.tests_token_authorization_code import AuthorizationCodeTokenTestCase
from authserver.utils.utils import overwrite_dict


class RefreshTokenTestCase(TokenTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)

    @classmethod
    def get_rt_token_request_parameters(cls, **kwargs):

        params = {
            'grant_type': 'refresh_token',
            'refresh_token': '5q538sytrpxh9TIg6u8oULg9ufxdFs'
        }

        overwrite_dict(params, kwargs)

        return params


class AuthorizationCodeRefreshTokenTestCase(AuthorizationCodeTokenTestCase):

    def test_refresh_token(self):
        token, _ = self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), self.get_default_headers())
        old_dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']})

        response = self.do_token(RefreshTokenTestCase.get_rt_token_request_parameters(**{'refresh_token': token['refresh_token']}), self.get_default_headers())
        new_token, _, _ = self.assertAccessTokenOK(response, refresh_token=True, id_token=False)
        for k in ['expires_in', 'token_type', 'scope']:
            self.assertEqual(token[k], new_token[k])
        for k in ['access_token', 'refresh_token']:
            self.assertNotEqual(token[k], new_token[k])
        self.assertNotIn('id_token', new_token)
        self.assertNotIn('consent_date', new_token)

        new_dbtoken = TokenCollection.objects.find_one({'access_token': new_token['access_token'], 'refresh_token': new_token['refresh_token']})
        self.assertIsNone(TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']}))

        self.assertLess(old_dbtoken['expires_at'], new_dbtoken['expires_at'])
        self.assertLess(old_dbtoken['creation'], new_dbtoken['creation'])
        self.assertLess(old_dbtoken['refresh_token_expires_at'], new_dbtoken['refresh_token_expires_at'])
        self.assertLess(old_dbtoken['expiration'], new_dbtoken['expiration'])

        fields = ['access_token', 'refresh_token', 'id_token', 'expires_at', 'creation', 'refresh_token_expires_at', 'expiration']
        old_dbtoken = {k: v for k, v in old_dbtoken.items() if k not in fields}
        new_dbtoken = {k: v for k, v in new_dbtoken.items() if k not in fields}
        self.assertDictEqual(old_dbtoken, new_dbtoken)

    def test_renewed_refresh_token(self):
        token, _ = self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), self.get_default_headers())
        old_dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']})

        response = self.do_token(RefreshTokenTestCase.get_rt_token_request_parameters(**{'refresh_token': token['refresh_token']}), self.get_default_headers())
        new_token, _, _ = self.assertAccessTokenOK(response, refresh_token=True, id_token=False)

        new_dbtoken = TokenCollection.objects.find_one({'access_token': new_token['access_token'], 'refresh_token': new_token['refresh_token']})

        response = self.do_token(RefreshTokenTestCase.get_rt_token_request_parameters(**{'refresh_token': new_token['refresh_token']}), self.get_default_headers())
        renewed_token, _, _ = self.assertAccessTokenOK(response, refresh_token=True, id_token=False)

        for k in ['expires_in', 'token_type', 'scope']:
            self.assertEqual(renewed_token[k], new_token[k])
        for k in ['access_token', 'refresh_token']:
            self.assertNotEqual(renewed_token[k], new_token[k])
        self.assertNotIn('id_token', renewed_token)
        self.assertNotIn('consent_date', renewed_token)

        renewed_dbtoken = TokenCollection.objects.find_one({'access_token': renewed_token['access_token'], 'refresh_token': renewed_token['refresh_token']})
        self.assertIsNone(TokenCollection.objects.find_one({'access_token': new_token['access_token'], 'refresh_token': new_token['refresh_token']}))
        self.assertIsNone(TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']}))

        self.assertLess(new_dbtoken['expires_at'], renewed_dbtoken['expires_at'])
        self.assertLess(new_dbtoken['creation'], renewed_dbtoken['creation'])
        self.assertLess(new_dbtoken['refresh_token_expires_at'], renewed_dbtoken['refresh_token_expires_at'])
        self.assertLess(new_dbtoken['expiration'], renewed_dbtoken['expiration'])

        fields = ['access_token', 'refresh_token', 'id_token', 'expires_at', 'creation', 'refresh_token_expires_at', 'expiration']
        old_dbtoken = {k: v for k, v in old_dbtoken.items() if k not in fields}
        renewed_dbtoken = {k: v for k, v in new_dbtoken.items() if k not in fields}
        self.assertDictEqual(old_dbtoken, renewed_dbtoken)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_token_ok_client_secret_post(self):
        token, _ = self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), self.get_default_headers())
        token_params = RefreshTokenTestCase.get_rt_token_request_parameters(**{'refresh_token': token['refresh_token']})
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_token(token_params, {})
        self.assertAccessTokenOK(response, refresh_token=True, id_token=False)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_jwt_bearer(self, m):
        self.do_mocking(m)

        token, _ = self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), self.get_default_headers())
        token_params = RefreshTokenTestCase.get_rt_token_request_parameters(**{'refresh_token': token['refresh_token']})
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_token(token_params, {})
        self.assertAccessTokenOK(response, refresh_token=True, id_token=False)

    def test_json_content_type(self):
        token, _ = self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), self.get_default_headers())
        token_params = RefreshTokenTestCase.get_rt_token_request_parameters(**{'refresh_token': token['refresh_token']})
        client = Client()
        response = client.post('/oauth2/token',
                               data=json.dumps(token_params),
                               content_type='application/json', **self.get_default_headers())
        self.assertAccessTokenOK(response, refresh_token=True, id_token=False)

    def test_no_refresh_token(self):
        self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), self.get_default_headers())
        response = self.do_token(RefreshTokenTestCase.get_rt_token_request_parameters(**{'refresh_token': 'foo'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_grant')

    def test_reuse_refresh_token(self):
        token, _ = self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), self.get_default_headers())

        response = self.do_token(RefreshTokenTestCase.get_rt_token_request_parameters(**{'refresh_token': token['refresh_token']}), self.get_default_headers())
        self.assertAccessTokenOK(response, refresh_token=True, id_token=False)

        response = self.do_token(RefreshTokenTestCase.get_rt_token_request_parameters(**{'refresh_token': token['refresh_token']}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_grant')


class AuthorizationCodeRefreshTokenErrorTestCase(AuthorizationCodeTokenTestCase):

    def test_wrong_content_type(self):
        client = Client()
        response = client.post('/oauth2/token',
                               data='foo',
                               content_type='text/plain', **self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid content type.')

    def test_json_duplicated_params(self):
        client = Client()
        response = client.post('/oauth2/token',
                               data='{"refresh_token": "abcdefghijklmnnopqrstuvwxyz", "refresh_token": "abcdefghijklmnnopqrstuvwxyz"}',
                               content_type='application/json', **self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', "Invalid JSON: JSON parse error - 'refresh_token' key is already present in JSON object.")

    def test_json_wrong_format(self):
        client = Client()
        response = client.post('/oauth2/token',
                               data='foo',
                               content_type='application/json', **self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid JSON: Expecting value: line 1 column 1 (char 0).')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_multiple_auths(self):
        token, _ = self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), self.get_default_headers())
        token_params = RefreshTokenTestCase.get_rt_token_request_parameters(**{'refresh_token': token['refresh_token']})
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_token(token_params, self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Multiple authentication mechanisms.')
