import json
from urllib.parse import urlparse, parse_qs
from uuid import uuid4

from django.test.client import Client
from django.test.utils import override_settings

from authserver.oauth2.models import ApplicationCollection, UserPcrCollection, \
    AuthenticationCollection, CodeCollection
from authserver.oauth2.tests.tests_basic import BasicTestCase, APPLICATION, USER_PCR, USER_PHONE_IDENTITY
from authserver.utils.utils import overwrite_dict

JWT_AUTHENTICATE_PAYLOAD = {
    'type': 'object',
    'properties': {
        'nonce': {
            'type': 'string'
        },
        'aud': {
            'type': 'string'
        },
        'iss': {
            'type': 'string'
        },
        'acr_values': {
            'type': 'string'
        },
        'prompt': {
            'type': 'string'
        },
        'max_age': {
            'type': 'string',
            'pattern': r'^(0|[1-9][0-9]*)$'
        },
        'redirect_uri': {
            'type': 'string',
            'format': 'uri'
        },
        'client_id': {
            'type': 'string'
        },
        'client_name': {
            'type': 'string'
        },
        'login_hint': {
            'type': 'string'
        },
        'exp': {
            'type': 'integer',
        },
        'iat': {
            'type': 'integer',
        },
        'scopes': {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        'claims': {
            'type': 'object',
        }
    },
    'required': ['nonce', 'aud', 'iss', 'client_id', 'redirect_uri', 'exp', 'iat'],
    'additionalProperties': False
}


class AuthorizationCodeTestCase(BasicTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)
        UserPcrCollection.objects.insert_one(USER_PCR)

    def assertSpOkRedirection(self, response, url, url_params={}):
        self.assertEqual(response.status_code, 302)
        location = response['location']
        parse_result = urlparse(location)
        self.assertEqual(location.split('?')[0], url)

        params = parse_qs(parse_result.query)
        for param in url_params:
            self.assertIn(param, params)
            self.assertEqual(params[param][0], url_params[param])

        self.assertIn('code', params)

        return params['code'][0], params['state'][0] if 'state' in params else None

    def assertSpErrorRedirection(self, response, url, error, error_description=None, url_params={}):
        self.assertEqual(response.status_code, 302)
        location = response['location']
        parse_result = urlparse(location)
        self.assertEqual(location.split('?')[0], url)

        params = parse_qs(parse_result.query)
        for param in url_params:
            self.assertIn(param, params)
            self.assertEqual(params[param][0], url_params[param])

        self.assertIn('error', params)
        self.assertEqual(params['error'][0], error)
        if error_description:
            self.assertIn('error_description', params)
            self.assertEqual(params['error_description'][0], error_description)
        else:
            self.assertNotIn('error_description', params)

    @classmethod
    def do_authorize(cls, params):
        client = Client()
        return client.get('/oauth2/authorize', params)

    @classmethod
    def get_authorize_parameters(cls, **kwargs):
        params = {
            'client_id': APPLICATION['_id'],
            'redirect_uri': APPLICATION['redirect_uri'],
            'response_type': 'code',
            'response_mode': 'query',
            'scope': 'openid phone',
            'state': str(uuid4()),
            'nonce': str(uuid4()),
            'prompt': 'login',
            'display': 'page',
            'login_hint': 'MSISDN:' + USER_PHONE_IDENTITY[1:],
            'acr_values': '2',
            'max_age': '86400',
            'client_name': APPLICATION['name'][0],
            'claims': json.dumps({"id_token": {"phone_number": None}})
        }
        overwrite_dict(params, kwargs)
        return params

    @classmethod
    def do_code(cls, params):
        response = cls.do_authorize(params)
        params = parse_qs(urlparse(response['location']).query)
        return params['code'][0]


class AuthorizationCodeOKTestCase(AuthorizationCodeTestCase):

    def test_code_ok(self):
        params = self.get_authorize_parameters()
        response = self.do_authorize(params)
        authentication = AuthenticationCollection.objects.find_one({AuthenticationCollection.FIELD_STATE: params['state']})
        self.assertIsNotNone(authentication)

        code, state = self.assertSpOkRedirection(response, APPLICATION['redirect_uri'])

        dbcode = CodeCollection.objects.find_one({CodeCollection.FIELD_NONCE: params['nonce']})
        self.assertIsNotNone(dbcode)
        self.assertEqual(code, dbcode[CodeCollection.FIELD_ID])
        self.assertEqual(state, params['state'])

        return code

    def test_no_state(self):
        params = self.get_authorize_parameters(**{'state': None})
        response = self.do_authorize(params)
        code, state = self.assertSpOkRedirection(response, APPLICATION['redirect_uri'])
        self.assertIsNotNone(code)
        self.assertIsNone(state)

    def test_fragment_response_mode(self):
        params = self.get_authorize_parameters(**{'response_mode': 'fragment'})
        response = self.do_authorize(params)
        url = urlparse(response['location'])
        self.assertGreater(len(url[5]), 0)
        redirect_params = parse_qs(url[5])
        self.assertIn('code', redirect_params)
        self.assertIn('state', redirect_params)


class AuthorizationCodeErrorTestCase(AuthorizationCodeTestCase):

    def test_invalid_method(self):
        client = Client()
        response = client.post('/oauth2/authorize')
        self.assertEqual(response.status_code, 405)

    def test_invalid_grant(self):
        ApplicationCollection.objects.update_one(
            {'_id': APPLICATION['_id']},
            {
                '$set': {
                     'grants': [
                        {
                            'grant_type': 'client_credentials',
                            'scopes': ['openid', 'phone']
                        }
                     ]
                }
            }
        )
        response = self.do_authorize(self.get_authorize_parameters())
        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'unauthorized_client')

    @override_settings(ERROR_DESCRIPTION_FORMAT='lowercase')
    def test_error_description_format(self):
        response = self.do_authorize(self.get_authorize_parameters(**{'client_id': 'Wrong'}))
        self.assertErrorPage(response, 400, 'invalid_request', 'invalid client_id parameter value')


class AuthorizationCodeParametersTestCase(AuthorizationCodeTestCase):

    def test_wrong_query_params(self):
        client = Client()
        response = client.get('/oauth2/authorize?=&&?')
        self.assertErrorPage(response, 400, 'invalid_request', 'Unable to parse query string.')

    def test_missing_parameters(self):
        # Fatal
        for param, error in [('client_id', 'Missing client_id parameter.'), ('redirect_uri', 'Missing redirect URI.')]:
            response = self.do_authorize(self.get_authorize_parameters(**{param: None}))
            self.assertErrorPage(response, 400, 'invalid_request', error)

        # Redirect
        for param in ['response_type', 'acr_values', 'client_name']:
            response = self.do_authorize(self.get_authorize_parameters(**{param: None}))
            self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'invalid_request', f'Missing {param} parameter.')

    def test_duplicated_parameters(self):
        client = Client()
        for param in ['request', 'client_id', 'response_type', 'redirect_uri', 'scope', 'state', 'nonce',
                      'acr_values', 'response_mode', 'nonce', 'display', 'prompt', 'claims',
                      'max_age', 'ui_locales', 'id_token_hint', 'login_hint', 'acr_values', 'client_name']:
            response = client.get(f'/oauth2/authorize?{param}=foo&{param}=bar')
            self.assertErrorPage(response, 400, 'invalid_request', f'Duplicate {param} parameter.')


class AuthorizationCodeParameterValuesTestCase(AuthorizationCodeTestCase):

    def test_wrong_client_id_parameter(self):
        response = self.do_authorize(self.get_authorize_parameters(**{'client_id': 'Wrong'}))
        self.assertErrorPage(response, 400, 'invalid_request', 'Invalid client_id parameter value.')

    def test_inactive_client_id_parameter(self):
        ApplicationCollection.objects.update_one({'_id': APPLICATION['_id']}, {'$set': {'status': 'inactive'}})

        response = self.do_authorize(self.get_authorize_parameters())
        self.assertErrorPage(response, 400, 'invalid_request', 'Invalid client_id parameter value.')

    def test_wrong_redirect_uri_parameter(self):
        response = self.do_authorize(self.get_authorize_parameters(**{'redirect_uri': 'http://www.foo.bar/wrong-callback'}))
        self.assertErrorPage(response, 400, 'invalid_request', 'Mismatching redirect URI.')

    def test_wrong_response_type_parameter(self):
        response = self.do_authorize(self.get_authorize_parameters(**{'response_type': 'Wrong'}))
        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'unsupported_response_type')

    def test_wrong_acr_values_parameter(self):
        response = self.do_authorize(self.get_authorize_parameters(**{'acr_values': '7 2'}))
        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'invalid_request', 'Invalid acr_values parameter value.')

    def test_wrong_max_age_parameter(self):
        for max_age in ['a', '-234']:
            response = self.do_authorize(self.get_authorize_parameters(**{'max_age': max_age}))
            self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'invalid_request', 'Invalid max_age parameter value.')

    def test_wrong_scope_parameter(self):
        response = self.do_authorize(self.get_authorize_parameters(**{'scope': 'openid wrong'}))
        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'invalid_scope')

    def test_wrong_code_challenge_method(self):
        response = self.do_authorize(self.get_authorize_parameters(**{'code_challenge_method': 'foo'}))
        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'invalid_request', 'Invalid code_challenge_method parameter value: Unsupported method.')

    def test_wrong_code_challenge_length(self):
        response = self.do_authorize(self.get_authorize_parameters(**{'code_challenge': 'foo', 'code_challenge_method': 'S256'}))
        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'invalid_request', 'Invalid code_challenge parameter value: Invalid length (42<size<129).')


class AuthorizationCodeClientNameTestCase(AuthorizationCodeTestCase):

    def test_wrong_client_name_parameter(self):
        response = self.do_authorize(self.get_authorize_parameters(**{'client_name': 'Wrong'}))
        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'invalid_request', 'Mismatching client_name.')


class AuthorizationCodeRedirectUriWithParamsTestCase(AuthorizationCodeTestCase):

    def setUp(self):
        super().setUp()
        self.redirect_uri = APPLICATION['redirect_uri'] + '?foo=bar&foo2=bar2'
        ApplicationCollection.objects.update_one({'_id': APPLICATION['_id']}, {'$set': {'redirect_uri': self.redirect_uri}})

    def test_params_in_redirection(self):
        params = self.get_authorize_parameters(**{'redirect_uri': self.redirect_uri})
        response = self.do_authorize(params)
        code, _ = self.assertSpOkRedirection(response, APPLICATION['redirect_uri'], {'foo': 'bar', 'foo2': 'bar2'})
        self.assertIsNotNone(code)

    def test_params_in_error_redirection(self):
        params = self.get_authorize_parameters(**{'redirect_uri': self.redirect_uri, 'scope': 'openid wrong'})
        response = self.do_authorize(params)
        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'invalid_scope', url_params={'foo': 'bar', 'foo2': 'bar2'})

    def test_ordered_params_in_redirection(self):
        params = self.get_authorize_parameters(**{'redirect_uri': APPLICATION['redirect_uri'] + '?foo2=bar2&foo=bar'})
        response = self.do_authorize(params)
        self.assertErrorPage(response, 400, 'invalid_request', 'Mismatching redirect URI.')

    def test_alien_params_in_redirect_uri(self):
        params = self.get_authorize_parameters(**{'redirect_uri': self.redirect_uri + '&foo3=bar3', 'scope': 'openid wrong'})
        response = self.do_authorize(params)
        self.assertErrorPage(response, 400, 'invalid_request', 'Mismatching redirect URI.')

