from django.test.client import Client

from authserver.oauth2.tests.tests_authorize import AuthorizationCodeTestCase
from authserver.oauth2.tests.tests_token_authorization_code import AuthorizationCodeTokenTestCase


class UserinfoTestCase(AuthorizationCodeTokenTestCase):

    def setUp(self):
        super().setUp()

    @classmethod
    def do_userinfo(cls, headers):
        client = Client()
        return client.get('/oauth2/userinfo', **headers)

    @classmethod
    def get_userinfo_headers(cls, token):
        return {
            'HTTP_AUTHORIZATION': f'Bearer {token}'
        }


class UserinfoOkTestCase(UserinfoTestCase):

    def test_ok(self):
        response = AuthorizationCodeTokenTestCase.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(),
                                                                self.get_token_request_parameters(),
                                                                self.get_default_headers())
        token = response.json()['access_token']

        response = self.do_userinfo(self.get_userinfo_headers(token))
        body = response.json()

        self.assertDictEqual(body,
                             {
                                'phone_number': '+34618051526',
                                'phone_number_verified': True,
                                'sub': '2128c01f-dcc8-4fde-a74e-eba2f9b1a3af'
                             })

    def test_only_sub(self):
        response = AuthorizationCodeTokenTestCase.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(scope='openid'),
                                                                self.get_token_request_parameters(),
                                                                self.get_default_headers())
        token = response.json()['access_token']

        response = self.do_userinfo(self.get_userinfo_headers(token))
        body = response.json()

        self.assertDictEqual(body, {'sub': '2128c01f-dcc8-4fde-a74e-eba2f9b1a3af'})


class UserinfoErrorTestCase(UserinfoTestCase):

    def test_no_auth_header(self):
        response = self.do_userinfo({})
        self.assertJsonError(response, 401, 'invalid_token',
                             'The access token provided is expired, revoked, malformed, or invalid for other reasons.')

    def test_wrong_auth_header(self):
        for auth_header in ['foo', 'Basic foo']:
            response = self.do_userinfo({'HTTP_AUTHORIZATION': auth_header})
            self.assertJsonError(response, 401, 'invalid_token',
                                 'The access token provided is expired, revoked, malformed, or invalid for other reasons.')

    def test_wrong_token(self):
        response = self.do_userinfo(self.get_userinfo_headers('foo'))
        self.assertJsonError(response, 401, 'invalid_token',
                             'The access token provided is expired, revoked, malformed, or invalid for other reasons.')

    def test_insufficient_scope(self):
        response = AuthorizationCodeTokenTestCase.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(scope='phone'),
                                                                self.get_token_request_parameters(),
                                                                self.get_default_headers())

        token = response.json()['access_token']

        response = self.do_userinfo(self.get_userinfo_headers(token))
        self.assertJsonError(response, 403, 'insufficient_scope',
                             'The request requires higher privileges than provided by the access token.')






