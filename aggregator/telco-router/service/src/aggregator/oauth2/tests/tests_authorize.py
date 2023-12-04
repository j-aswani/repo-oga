from datetime import datetime
from urllib.parse import urlparse, parse_qsl
from uuid import uuid4

import requests_mock
from django.conf import settings
from django.test.client import Client
from django.test.utils import override_settings
from freezegun import freeze_time

from aggregator.oauth2.models import ApplicationCollection
from aggregator.oauth2.tests.tests_basic import BasicTestCase, APPLICATION
from aggregator.utils.utils import overwrite_dict


class AuthorizationCodeTestCase(BasicTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)

    def assertOperatorRedirection(self, response, url, expected_params=None):
        self.assertEqual(response.status_code, 302)
        location = response['location']
        parse_result = urlparse(location)
        self.assertEqual(location.split('?')[0], url)

        params = dict(parse_qsl(parse_result.query))
        if expected_params is not None:
            self.assertDictContainsSubset(expected_params, params)

        return params.get('state', None)

    def assertSpOkRedirection(self, response, url, url_params={}):
        self.assertEqual(response.status_code, 302)
        location = response['location']
        parse_result = urlparse(location)
        self.assertEqual(location.split('?')[0], url)

        params = dict(parse_qsl(parse_result.query))
        for param in url_params:
            self.assertIn(param, params)
            self.assertEqual(params[param], url_params[param])

        self.assertIn('code', params)

        return params['code'], params['state'] if 'state' in params else None

    def assertSpErrorRedirection(self, response, url, error, error_description=None, url_params={}):
        self.assertEqual(response.status_code, 302)
        location = response['location']
        parse_result = urlparse(location)
        self.assertEqual(location.split('?')[0], url)

        params = dict(parse_qsl(parse_result.query))
        for param in url_params:
            self.assertIn(param, params)
            self.assertEqual(params[param], url_params[param])

        self.assertIn('error', params)
        self.assertEqual(params['error'], error)
        if error_description:
            self.assertIn('error_description', params)
            self.assertEqual(params['error_description'], error_description)
        else:
            self.assertNotIn('error_description', params)

    @classmethod
    def do_authorize(cls, params):
        client = Client()
        return client.get('/oauth2/authorize', params)

    @classmethod
    def do_callback(cls, params):
        client = Client()
        return client.get('/oauth2/authorize/callback', params)

    @classmethod
    def get_ok_params(cls, **kwargs):
        result = {
            'state': '3100346d-6f33-4cb5-bbbe-f83caf0d434f',
            'code': 'db95a649-83b1-4abd-8f85-2bb322777525'
        }
        overwrite_dict(result, kwargs)
        return result

    @classmethod
    def get_error_params(cls, **kwargs):
        result = {
            'state': '3100346d-6f33-4cb5-bbbe-f83caf0d434f',
            'error': 'access_denied',
            'error_description': 'authentication expired'
        }
        overwrite_dict(result, kwargs)
        return result

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
            'acr_values': '2',
            'max_age': '86400',
            'client_name': APPLICATION['name'][0]
        }
        overwrite_dict(params, kwargs)
        return params

    @classmethod
    def get_state_payload(cls, **kwargs):
        payload = {

        }
        overwrite_dict(payload, kwargs)
        return payload

    @classmethod
    def do_code(cls, params):
        response = cls.do_authorize(params)

        location = response['location']
        parse_result = urlparse(location)
        params = dict(parse_qsl(parse_result.query))

        response = cls.do_callback(cls.get_ok_params(**{'state': params['state']}))
        params = dict(parse_qsl(urlparse(response['location']).query))
        return params['code']


class AuthorizationCodeOKTestCase(AuthorizationCodeTestCase):

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_code_ok(self, m):
        self.do_mocking(m)

        params = self.get_authorize_parameters()
        response = self.do_authorize(params)
        param_state = params['state']

        del params['state']
        params['redirect_uri'] = f"{settings.AGGREGATOR_HOST}/oauth2/authorize/callback"
        aggregator_state = self.assertOperatorRedirection(response,
                                                          "http://oauth.operator.com/authorize",
                                                          expected_params=params)
        response = self.do_callback(self.get_ok_params(**{'state': aggregator_state}))

        code, state = self.assertSpOkRedirection(response, APPLICATION['redirect_uri'])

        self.assertIsNotNone(code)
        self.assertEqual(state, param_state)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_no_state(self, m):
        self.do_mocking(m)

        params = self.get_authorize_parameters(**{'state': None})
        response = self.do_authorize(params)

        params['redirect_uri'] = f"{settings.AGGREGATOR_HOST}/oauth2/authorize/callback"
        aggregator_state = self.assertOperatorRedirection(response,
                                                          "http://oauth.operator.com/authorize",
                                                          expected_params=params)
        response = self.do_callback(self.get_ok_params(**{'state': aggregator_state}))

        code, state = self.assertSpOkRedirection(response, APPLICATION['redirect_uri'])

        self.assertIsNotNone(code)
        self.assertIsNone(state)


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
        for param in ['response_type']:
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

    def test_wrong_scope_parameter(self):
        response = self.do_authorize(self.get_authorize_parameters(**{'scope': 'openid wrong'}))
        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'invalid_scope')


class AuthorizationCodeOperatorErrorTestCase(AuthorizationCodeTestCase):

    def test_no_params(self):
        client = Client()
        response = client.get('/oauth2/authorize/callback')
        self.assertErrorPage(response, 400, 'invalid_request', 'Missing state parameter.')

    def test_wrong_state(self):
        client = Client()
        response = client.get('/oauth2/authorize/callback', {'state': 'foo'})
        self.assertErrorPage(response, 400, 'invalid_request', 'Invalid JWT: Invalid JWT content.')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_telcofinder_unknown_error(self, m):
        self.do_mocking(m)
        m.get("http://api.aggregator.com/.well-known/webfinger", status_code=404)

        params = self.get_authorize_parameters()
        response = self.do_authorize(params)
        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'access_denied', error_description='Unknown user.')


    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_operator_error(self, m):
        self.do_mocking(m)

        params = self.get_authorize_parameters()
        response = self.do_authorize(params)
        param_state = params['state']

        del params['state']
        params['redirect_uri'] = f"{settings.AGGREGATOR_HOST}/oauth2/authorize/callback"
        aggregator_state = self.assertOperatorRedirection(response,
                                                          "http://oauth.operator.com/authorize",
                                                          expected_params=params)
        response = self.do_callback(self.get_error_params(**{'state': aggregator_state}))

        self.assertSpErrorRedirection(response, APPLICATION['redirect_uri'], 'access_denied', 'Authentication expired.',
                                      url_params={'state': param_state})

