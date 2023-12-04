import json
from base64 import b64encode
from copy import deepcopy
from urllib.parse import urlencode

import requests_mock
from django.conf import settings
from django.test.client import Client
from jsonschema import FormatChecker
from jsonschema.validators import validate

from authserver.oauth2.models import ApplicationCollection, TokenCollection
from authserver.oauth2.tests.tests_basic import APPLICATION, BasicTestCase
from authserver.oauth2.tests.tests_token import TokenTestCase
from authserver.oauth2.tests.tests_token_client_credentials import ClientCredentialsTokenTestCase
from authserver.utils.utils import overwrite_dict, to_epoch

INTROSPECTED_TOKEN_PAYLOAD = {
    'type': 'object',
    'properties': {
        'iss': {
            'type': 'string'
        },
        'aud': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'token_type': {
            'type': 'string',
            'enum': ['Bearer']
        },
        'scope': {
            'type': 'string'
        },
        'client_id': {
            'type': 'string'
        },
        'iat': {
            'type': 'integer'
        },
        'exp': {
            'type': 'integer'
        },
        'username': {
            'type': 'string'
        },
        'active': {
            'type': 'boolean',
            'enum': [True]
        }
    },
    'required': ['iss', 'aud', 'scope', 'client_id', 'token_type', 'iat', 'exp', 'active'],
    'additionalProperties': False
}


class IntrospectTokenTestCase(BasicTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)
        self.token = TokenTestCase.get_db_token()
        self.cc_token = ClientCredentialsTokenTestCase.get_db_token()
        TokenCollection.objects.insert_one(self.token)
        TokenCollection.objects.insert_one(self.cc_token)

    @classmethod
    def do_instrospection(cls, payload, headers, **kwargs):
        client = Client()
        return client.post('/oauth2/introspect', data=urlencode(payload), content_type='application/x-www-form-urlencoded', **headers)

    @classmethod
    def get_token_request_parameters(cls, **kwargs):
        params = {
            'token': '7eB6bgCzdyFRZKXWpP8SdBQRvdOlO8',
            'token_type_hint': 'access_token',
        }
        overwrite_dict(params, kwargs)
        return params

    def assertTokenOK(self, response):
        self.assertEqual(response.status_code, 200)
        token = response.json()

        try:
            validate(response.json(), schema=INTROSPECTED_TOKEN_PAYLOAD, format_checker=FormatChecker())
        except Exception as e:
            self.fail('Schema failed: %s' % str(e.args[0]))

        return token

    def assertNoToken(self, response):
        self.assertEqual(response.status_code, 200)
        token = response.json()
        self.assertDictEqual(token, {'active': False})


class IntrospectTokenOKTestCase(IntrospectTokenTestCase):

    def test_get_access_token(self):
        response = self.do_instrospection(self.get_token_request_parameters(**{'token': self.token['access_token']}), self.get_default_headers())
        token = self.assertTokenOK(response)

        self.assertEqual(token['iss'], settings.AUTHSERVER_HOST)
        self.assertEqual(token['scope'], ' '.join(self.token['scopes']))
        self.assertEqual(token['client_id'], APPLICATION['_id'])
        self.assertEqual(token['aud'], [APPLICATION['_id']])
        self.assertEqual(token['iat'], int(to_epoch(self.token['creation'])))
        self.assertEqual(token['exp'], int(to_epoch(self.token['expires_at'])))
        self.assertIn('username', token)
        self.assertEqual(token['username'], self.token['uid'])

    def test_get_user_untied_access_token(self):
        response = self.do_instrospection(self.get_token_request_parameters(**{'token': self.cc_token['access_token']}), self.get_default_headers())
        token = self.assertTokenOK(response)

        self.assertEqual(token['iss'], settings.AUTHSERVER_HOST)
        self.assertEqual(token['scope'], ' '.join(self.cc_token['scopes']))
        self.assertEqual(token['client_id'], APPLICATION['_id'])
        self.assertEqual(token['aud'], [APPLICATION['_id']])
        self.assertEqual(token['iat'], int(to_epoch(self.cc_token['creation'])))
        self.assertEqual(token['exp'], int(to_epoch(self.cc_token['expires_at'])))
        self.assertNotIn('username', token)

    def test_get_access_token_without_hint(self):
        response = self.do_instrospection(self.get_token_request_parameters(**{'token': self.token['access_token'], 'token_type_hint': None}), self.get_default_headers())
        self.assertTokenOK(response)

    def test_get_access_token_with_wrong_hint(self):
        response = self.do_instrospection(self.get_token_request_parameters(
            **{'token': self.token['access_token'], 'token_type_hint': 'refresh_token'}), self.get_default_headers())
        self.assertTokenOK(response)

    def test_get_refresh_token(self):
        response = self.do_instrospection(self.get_token_request_parameters(
            **{'token': self.token['refresh_token'], 'token_type_hint': 'refresh_token'}), self.get_default_headers())
        token = self.assertTokenOK(response)

        self.assertEqual(token['iss'], settings.AUTHSERVER_HOST)
        self.assertEqual(token['scope'], ' '.join(self.token['scopes']))
        self.assertEqual(token['client_id'], APPLICATION['_id'])
        self.assertEqual(token['aud'], [APPLICATION['_id']])
        self.assertEqual(token['iat'], int(to_epoch(self.token['creation'])))
        self.assertEqual(token['exp'], int(to_epoch(self.token['refresh_token_expires_at'])))
        self.assertIn('username', token)
        self.assertEqual(token['username'], self.token['uid'])

    def test_get_refresh_token_without_hint(self):
        response = self.do_instrospection(self.get_token_request_parameters(**{'token': self.token['refresh_token'], 'token_type_hint': None}), self.get_default_headers())
        self.assertTokenOK(response)

    def test_get_refresh_token_with_wrong_hint(self):
        response = self.do_instrospection(self.get_token_request_parameters(
            **{'token': self.token['refresh_token'], 'token_type_hint': 'access_token'}), self.get_default_headers())
        self.assertTokenOK(response)

    def test_json_content_type(self):
        client = Client()
        response = client.post('/oauth2/introspect',
                               data=json.dumps(self.get_token_request_parameters(**{'token': self.token['refresh_token'], 'token_type_hint': None})),
                               content_type='application/json', **self.get_default_headers())
        self.assertTokenOK(response)

    def test_client_secret_post(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_instrospection(self.get_token_request_parameters(**{'client_id': APPLICATION['_id'], 'client_secret': APPLICATION['consumer_secret']}), {})
        self.assertTokenOK(response)

    @requests_mock.mock()
    def test_multiple_auths(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_instrospection(token_params, {})
        self.assertTokenOK(response)


class IntrospectTokenWrongValuesTestCase(IntrospectTokenTestCase):

    def test_get_wrong_access_token(self):
        response = self.do_instrospection(self.get_token_request_parameters(**{'token': 'foo'}), self.get_default_headers())
        self.assertNoToken(response)

    def test_get_wrong_refresh_token(self):
        response = self.do_instrospection(self.get_token_request_parameters(**{'token': 'foo', 'token_type_hint': 'refresh_token'}), self.get_default_headers())
        self.assertNoToken(response)

    def test_get_access_token_with_wrong_client_id(self):
        new_app = deepcopy(APPLICATION)
        new_app[ApplicationCollection.FIELD_ID] = 'foo'
        ApplicationCollection.objects.insert_one(new_app)
        headers = self.get_default_headers()
        headers['HTTP_AUTHORIZATION'] = self.get_authorization_header(new_app[ApplicationCollection.FIELD_ID], APPLICATION[ApplicationCollection.FIELD_CONSUMER_SECRET])

        response = self.do_instrospection(self.get_token_request_parameters(**{'token': self.token['access_token']}), headers)
        self.assertNoToken(response)

    def test_remove_access_token_without_token(self):
        response = self.do_instrospection(self.get_token_request_parameters(**{'token': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Missing token parameter.')

    def test_remove_access_token_with_wrong_hint(self):
        response = self.do_instrospection(self.get_token_request_parameters(**{'token': self.token['access_token'], 'token_type_hint': 'foo'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_token_type')


class IntrospectTokenErrorTestCase(IntrospectTokenTestCase):

    def test_wrong_method(self):
        client = Client()
        response = client.get('/oauth2/introspect', self.get_token_request_parameters(), self.get_default_headers())
        self.assertEqual(response.status_code, 405)

    def test_wrong_content_type(self):
        client = Client()
        response = client.post('/oauth2/introspect',
                               data='foo',
                               content_type='text/plain', **self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid content type.')

    def test_json_duplicated_params(self):
        client = Client()
        response = client.post('/oauth2/introspect',
                               data='{"token": "abcdefghijklmnnopqrstuvwxyz", "token": "abcdefghijklmnnopqrstuvwxyz", "token_type_hint": "access_token"}',
                               content_type='application/json', **self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', "Invalid JSON: JSON parse error - 'token' key is already present in JSON object.")

    def test_json_wrong_format(self):
        client = Client()
        response = client.post('/oauth2/introspect',
                               data='foo',
                               content_type='application/json', **self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid JSON: Expecting value: line 1 column 1 (char 0).')

    def test_no_auth(self):
        response = self.do_instrospection(self.get_token_request_parameters(**{'token': self.token['access_token']}), {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_empty_password(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        response = self.do_instrospection(token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_wrong_client(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = 'wrong'
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_instrospection(token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_wrong_password(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = 'wrong'
        response = self.do_instrospection(token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_client(self):
        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header('wrong', APPLICATION[ApplicationCollection.FIELD_CONSUMER_SECRET])
        }
        response = self.do_instrospection(self.get_token_request_parameters(), headers)
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_password(self):
        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header(APPLICATION[ApplicationCollection.FIELD_ID], 'wrong')
        }
        response = self.do_instrospection(self.get_token_request_parameters(), headers)
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_header(self):
        for value in ['foo', 'Basic foo', 'Basic ' + b64encode(f'{APPLICATION["_id"]}'.encode('utf-8')).decode('utf-8')]:
            headers = {'HTTP_AUTHORIZATION': value}
            response = self.do_instrospection(self.get_token_request_parameters(), headers)
            self.assertJsonError(response, 401, 'invalid_client')

    @requests_mock.mock()
    def test_multiple_auths(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_instrospection(token_params, self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Multiple authentication mechanisms.')
