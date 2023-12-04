import json
from base64 import b64encode
from copy import deepcopy
from datetime import datetime
from urllib.parse import urlencode

import requests_mock
from django.conf import settings
from django.test.client import Client
from freezegun.api import freeze_time

from authserver.oauth2.models import ApplicationCollection, TokenCollection
from authserver.oauth2.tests.tests_basic import APPLICATION, BasicTestCase, get_signed_jwt, SP_JWT_PRIVATE_KEY, USER_PCR
from authserver.utils.utils import overwrite_dict


class RevokeTokenTestCase(BasicTestCase):

    TOKEN = {
        'access_token': 'abcdefgh',
        'refresh_token': 'ijklmnopq',
        'client_id': APPLICATION['_id'],
        'client_name': APPLICATION['name'][0],
        'grant_type': 'authorization_code',
        'scopes': ['openid', 'phone'],
        'uid': USER_PCR['user']
    }

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)
        TokenCollection.objects.insert_one(self.TOKEN)

    @classmethod
    def do_revocation(cls, payload, headers, **kwargs):
        client = Client()
        return client.post('/oauth2/revoke', data=urlencode(payload), content_type='application/x-www-form-urlencoded', **headers)

    @classmethod
    def get_token_request_parameters(cls, **kwargs):
        params = {
            'token': 'abcdefghijklmnnopqrstuvwxyz',
            'token_type_hint': 'access_token',
        }
        overwrite_dict(params, kwargs)
        return params


class RevokeTokenOKTestCase(RevokeTokenTestCase):

    def test_remove_access_token(self):
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)
        response = self.do_revocation(self.get_token_request_parameters(**{'token': self.TOKEN['access_token']}), self.get_default_headers())
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNone(token)

    def test_remove_access_token_without_hint(self):
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)
        response = self.do_revocation(self.get_token_request_parameters(**{'token': self.TOKEN['access_token'], 'token_type_hint': None}), self.get_default_headers())
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNone(token)

    def test_remove_access_token_with_wrong_hint(self):
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)
        response = self.do_revocation(self.get_token_request_parameters(**{'token': self.TOKEN['access_token'], 'token_type_hint': 'refresh_token'}), self.get_default_headers())
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNone(token)

    def test_remove_refresh_token(self):
        token = TokenCollection.objects.find_one({'refresh_token': self.TOKEN['refresh_token']})
        self.assertIsNotNone(token)
        response = self.do_revocation(self.get_token_request_parameters(**{'token': self.TOKEN['refresh_token'], 'token_type_hint': 'refresh_token'}), self.get_default_headers())
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'refresh_token': self.TOKEN['refresh_token']})
        self.assertIsNone(token)

    def test_remove_refresh_token_without_hint(self):
        token = TokenCollection.objects.find_one({'refresh_token': self.TOKEN['refresh_token']})
        self.assertIsNotNone(token)
        response = self.do_revocation(self.get_token_request_parameters(**{'token': self.TOKEN['refresh_token'], 'token_type_hint': None}), self.get_default_headers())
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'refresh_token': self.TOKEN['refresh_token']})
        self.assertIsNone(token)

    def test_remove_refresh_token_with_wrong_hint(self):
        token = TokenCollection.objects.find_one({'refresh_token': self.TOKEN['refresh_token']})
        self.assertIsNotNone(token)
        response = self.do_revocation(self.get_token_request_parameters(**{'token': self.TOKEN['refresh_token']}), self.get_default_headers())
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'refresh_token': self.TOKEN['refresh_token']})
        self.assertIsNone(token)

    def test_json_content_type(self):
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)
        client = Client()
        response = client.post('/oauth2/revoke',
                               data=json.dumps(self.get_token_request_parameters(**{'token': self.TOKEN['access_token'], 'token_type_hint': None})),
                               content_type='application/json', **self.get_default_headers())
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNone(token)

    def test_client_secret_post(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = APPLICATION['consumer_secret']
        token_params['token'] = self.TOKEN['access_token']
        response = self.do_revocation(self.get_token_request_parameters(**token_params), {})
        self.assertEqual(response.status_code, 200)

    @requests_mock.mock()
    def test_jwt_bearer(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        token_params['token'] = self.TOKEN['access_token']
        response = self.do_revocation(self.get_token_request_parameters(**token_params), {})
        self.assertEqual(response.status_code, 200)


class RevokeTokenWrongValuesTestCase(RevokeTokenTestCase):

    def test_remove_wrong_access_token(self):
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)
        response = self.do_revocation(self.get_token_request_parameters(**{'token': 'foo'}), self.get_default_headers())
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)

    def test_remove_wrong_refresh_token(self):
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)
        response = self.do_revocation(self.get_token_request_parameters(**{'token': 'foo', 'token_type_hint': 'refresh_token'}), self.get_default_headers())
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)

    def test_remove_wrong_token(self):
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)
        response = self.do_revocation(self.get_token_request_parameters(**{'token': 'foo', 'token_type_hint': None}), self.get_default_headers())
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)

    def test_remove_access_token_with_wrong_client_id(self):
        new_app = deepcopy(APPLICATION)
        new_app[ApplicationCollection.FIELD_ID] = 'foo'
        ApplicationCollection.objects.insert_one(new_app)
        headers = self.get_default_headers()
        headers['HTTP_AUTHORIZATION'] = self.get_authorization_header(new_app[ApplicationCollection.FIELD_ID], APPLICATION[ApplicationCollection.FIELD_CONSUMER_SECRET])

        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)
        response = self.do_revocation(self.get_token_request_parameters(**{'token': self.TOKEN['access_token']}), headers)
        self.assertEqual(response.status_code, 200)
        token = TokenCollection.objects.find_one({'access_token': self.TOKEN['access_token']})
        self.assertIsNotNone(token)

    def test_remove_access_token_with_wrong_hint(self):
        response = self.do_revocation(self.get_token_request_parameters(**{'token': self.TOKEN['access_token'], 'token_type_hint': 'foo'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_token_type')


class RevokeTokenErrorTestCase(RevokeTokenTestCase):

    def test_wrong_method(self):
        client = Client()
        response = client.get('/oauth2/revoke', self.get_token_request_parameters(), self.get_default_headers())
        self.assertEqual(response.status_code, 405)

    def test_wrong_content_type(self):
        client = Client()
        response = client.post('/oauth2/revoke',
                               data='foo',
                               content_type='text/plain', **self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid content type.')

    def test_json_duplicated_params(self):
        client = Client()
        response = client.post('/oauth2/revoke',
                               data='{"token": "abcdefghijklmnnopqrstuvwxyz", "token": "abcdefghijklmnnopqrstuvwxyz", "token_type_hint": "access_token"}',
                               content_type='application/json', **self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', "Invalid JSON: JSON parse error - 'token' key is already present in JSON object.")

    def test_json_wrong_format(self):
        client = Client()
        response = client.post('/oauth2/revoke',
                               data='foo',
                               content_type='application/json', **self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid JSON: Expecting value: line 1 column 1 (char 0).')

    def test_missing_parameters(self):
        response = self.do_revocation(self.get_token_request_parameters(**{'token': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Missing token parameter.')

    def test_no_auth(self):
        response = self.do_revocation(self.get_token_request_parameters(**{'token': self.TOKEN['access_token']}), {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_empty_password(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        response = self.do_revocation(token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_wrong_client(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = 'wrong'
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_revocation(token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_wrong_password(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = 'wrong'
        response = self.do_revocation(token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_client(self):
        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header('wrong', APPLICATION[ApplicationCollection.FIELD_CONSUMER_SECRET])
        }
        response = self.do_revocation(self.get_token_request_parameters(), headers)
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_password(self):
        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header(APPLICATION[ApplicationCollection.FIELD_ID], 'wrong')
        }
        response = self.do_revocation(self.get_token_request_parameters(), headers)
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_header(self):
        for value in ['foo', 'Basic foo', 'Basic ' + b64encode(f'{APPLICATION["_id"]}'.encode('utf-8')).decode('utf-8')]:
            headers = {'HTTP_AUTHORIZATION': value}
            response = self.do_revocation(self.get_token_request_parameters(), headers)
            self.assertJsonError(response, 401, 'invalid_client')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_multiple_auths(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = APPLICATION['consumer_secret']
        token_params['token'] = self.TOKEN['access_token']
        response = self.do_revocation(self.get_token_request_parameters(**token_params), {})
        self.assertJsonError(response, 400, 'invalid_request', 'Multiple authentication mechanisms.')
