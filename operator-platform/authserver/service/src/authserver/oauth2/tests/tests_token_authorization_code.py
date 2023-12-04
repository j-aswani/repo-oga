import json
import time
from base64 import b64encode
from copy import deepcopy
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import requests_mock
from django.conf import settings
from django.test.client import Client
from django.test.utils import override_settings
from freezegun.api import freeze_time

from authserver.oauth2.models import ApplicationCollection, UserPcrCollection, TokenCollection
from authserver.oauth2.tests.tests_authorize import AuthorizationCodeTestCase
from authserver.oauth2.tests.tests_basic import APPLICATION, USER_PCR, get_signed_jwt, SP_JWT_PRIVATE_KEY
from authserver.oauth2.tests.tests_token import TokenTestCase
from authserver.utils.utils import overwrite_dict


class AuthorizationCodeTokenTestCase(TokenTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)
        UserPcrCollection.objects.insert_one(USER_PCR)

    @classmethod
    def get_token_request_parameters(cls, **kwargs):
        params = {
            'code': 'abcdefghijklmnnopqrstuvwxyz',
            'redirect_uri': APPLICATION['redirect_uri'],
            'grant_type': 'authorization_code'
        }
        overwrite_dict(params, kwargs)
        return params

    @classmethod
    def do_code_token(cls, authorize_params, token_params, headers):
        code = AuthorizationCodeTestCase.do_code(authorize_params)
        token_params['code'] = code
        return cls.do_token(token_params, headers)

    def _test_token_ok(self, authorize_params, token_params, headers):
        response = self.do_code_token(authorize_params, token_params, headers)
        token, _, id_token_data = self.assertAccessTokenOK(response, refresh_token=True, id_token=True)
        return token, id_token_data

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
            'scopes': ['openid', 'phone'],
            'sub': USER_PCR['_id'],
            'uid': USER_PCR['user']
        }
        overwrite_dict(token, kwargs)
        return token


class AuthorizationCodeTokenOKTestCase(AuthorizationCodeTokenTestCase):

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_token_ok(self):
        authorize_params = AuthorizationCodeTestCase.get_authorize_parameters()
        token, id_token_data = self._test_token_ok(authorize_params, self.get_token_request_parameters(), self.get_default_headers())
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token'], 'refresh_token': token['refresh_token'], 'id_token': token['id_token']}))
        self.assertDictContainsSubset(self.get_id_token(**{'nonce': authorize_params['nonce']}), id_token_data)
        self.assertHash(token['access_token'], id_token_data['at_hash'])
        self.assertDictContainsSubset(self.get_jwt_access_token(), self.get_access_token_data(token['access_token']))

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_no_scope(self):
        authorize_params = AuthorizationCodeTestCase.get_authorize_parameters(**{'scope': None})
        token, id_token_data = self._test_token_ok(authorize_params, self.get_token_request_parameters(), self.get_default_headers())
        dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']})
        self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token'], 'refresh_token': token['refresh_token'], 'id_token': token['id_token'], 'scopes': ['openid', 'phone', 'atp']}))
        self.assertDictContainsSubset(self.get_id_token(**{'nonce': authorize_params['nonce']}), id_token_data)
        self.assertHash(token['access_token'], id_token_data['at_hash'])
        self.assertDictContainsSubset(self.get_jwt_access_token(**{'scopes': ['openid', 'phone', 'atp']}), self.get_access_token_data(token['access_token']))

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_client_secret_post(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = APPLICATION['consumer_secret']
        self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), token_params, {})

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_jwt_bearer(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), token_params, {})

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_no_nonce(self):
        authorize_params = AuthorizationCodeTestCase.get_authorize_parameters(**{'nonce': None})
        _, id_token_data = self._test_token_ok(authorize_params, self.get_token_request_parameters(), self.get_default_headers())
        self.assertDictContainsSubset(self.get_id_token(**{'nonce': None}), id_token_data)
        self.assertNotIn('nonce', id_token_data)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_no_claims(self):
        authorize_params = AuthorizationCodeTestCase.get_authorize_parameters(**{'claims': None})
        response = AuthorizationCodeTestCase.do_authorize(authorize_params)
        code = parse_qs(urlparse(response['location']).query)['code'][0]
        _, id_token_data = self._test_token_ok(authorize_params, self.get_token_request_parameters(**{'code': code}), self.get_default_headers())
        self.assertNotIn('phone_number', id_token_data)

    def test_json_content_type(self):
        code = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        token_params = self.get_token_request_parameters()
        token_params['code'] = code
        client = Client()
        response = client.post('/oauth2/token',
                               data=json.dumps(token_params),
                               content_type='application/json', **self.get_default_headers())
        self.assertAccessTokenOK(response, refresh_token=True, id_token=True)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_login_hint(self):
        login_hints = [('ENCR_MSISDN:a73eaa4c03ebc0bdd71a140f8039fe3a80d2b70dd350331f6f78904d48dbd8725c0566e460460e89ed5ca9df24930464e5507aaf85727264e09a7f2c7a16fde1e2b72edf599a0e54d4725bcca0a9ba4d0e4a2346c28d90280948424d5ffbd4c4b5d5c53ddba78f0db0ec5d9a760f84343b175d816f59956523ea2652a2e334607d00493d312bb3ca4d86701988ab48cb4f36e10132ec22f1d686361f6532ec122cc61e6c8b4424b1310c0448772fa9b3e07397056c0998c2172b663000e217fb4ecf968b6e357fd04f32fd4869837258969f2673090e7dba11d8cb66cbf09ab6433801e6595bd04dee86c9c8fd285a888b3b83cdeda174b067e0b984d4d01b61', 'RwvX5UIwI78H7JwUMzk2Xzn9OqATV4-iU29Y0Rb4MUw'),
                       ('PCR:' + USER_PCR['_id'], 'regp6UPSkbj-1iGMSWtWWwe1yfbduVk7OZB5Z_z9Wl8')]
        for lh, hashed in login_hints:
            authorize_params = AuthorizationCodeTestCase.get_authorize_parameters(**{'login_hint': lh})
            token, id_token_data = self._test_token_ok(authorize_params, self.get_token_request_parameters(), self.get_default_headers())
            dbtoken = TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']})
            self.assertDbTokenEqual(dbtoken, self.get_db_token(**{'access_token': token['access_token'], 'refresh_token': token['refresh_token'], 'id_token': token['id_token']}))
            self.assertDictContainsSubset(self.get_id_token(**{'nonce': authorize_params['nonce']}), id_token_data)


class AuthorizationCodeTokenErrorTestCase(AuthorizationCodeTokenTestCase):

    def test_no_auth(self):
        response = self.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_empty_password(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        response = self.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(), token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_wrong_client(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = 'wrong'
        token_params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(), token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_post_wrong_password(self):
        token_params = self.get_token_request_parameters()
        token_params['client_id'] = APPLICATION['_id']
        token_params['client_secret'] = 'wrong'
        response = self.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(), token_params, {})
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_client(self):
        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header('wrong', APPLICATION[ApplicationCollection.FIELD_CONSUMER_SECRET])
        }
        response = self.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), headers)
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_password(self):
        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header(APPLICATION[ApplicationCollection.FIELD_ID], 'wrong')
        }
        response = self.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), headers)
        self.assertJsonError(response, 401, 'invalid_client')

    def test_client_secret_basic_wrong_header(self):
        for value in ['foo', 'Basic foo', 'Basic ' + b64encode(f'{APPLICATION["_id"]}'.encode('utf-8')).decode('utf-8')]:
            headers = {'HTTP_AUTHORIZATION': value}
            response = self.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), headers)
            self.assertJsonError(response, 401, 'invalid_client')

    @requests_mock.mock()
    def test_multiple_auths(self, m):
        self.do_mocking(m)

        token_params = self.get_token_request_parameters()
        token_params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        token_params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_code_token(AuthorizationCodeTestCase.get_authorize_parameters(), token_params, self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Multiple authentication mechanisms.')

    def test_missing_parameters(self):
        code = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'redirect_uri': None, 'code': code}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Missing redirect URI.')

        AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'code': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', f'Missing code parameter.')

        AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'grant_type': None}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_grant_type')


class AuthorizationCodeTokenWrongValuesTestCase(AuthorizationCodeTokenTestCase):

    def test_wrong_grant_type(self):
        AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'grant_type': 'wrong'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'unsupported_grant_type')

    def test_wrong_redirect_uri(self):
        code = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'redirect_uri': 'https://www.wrong.com', 'code': code}),
                                 self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Mismatching redirect URI.')

    def test_wrong_code(self):
        _ = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())
        response = self.do_token(self.get_token_request_parameters(**{'code': 'wrong'}), self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_grant')

    def test_valid_code_with_wrong_client_id(self):
        app2 = deepcopy(APPLICATION)
        app2[ApplicationCollection.FIELD_ID] = '19c1afb8-f0ad-42b2-b6c0-cdfcdce051c7'
        app2[ApplicationCollection.FIELD_CONSUMER_SECRET] = 'eeae928b-0385-4090-abbe-7ff193934718'
        ApplicationCollection.objects.insert_one(app2)

        code = AuthorizationCodeTestCase.do_code(AuthorizationCodeTestCase.get_authorize_parameters())

        headers = {
            'HTTP_AUTHORIZATION': self.get_authorization_header(app2[ApplicationCollection.FIELD_ID], app2[ApplicationCollection.FIELD_CONSUMER_SECRET])
        }
        response = self.do_token(self.get_token_request_parameters(**{'code': code}), headers)
        self.assertJsonError(response, 400, 'invalid_grant')


class AuthorizationCodeTokenPkceTestCase(AuthorizationCodeTokenTestCase):

    code_verifier = 'LmHRhRoKlThYFQffM3mktXb1LTUnC94TOo-QmWaq6uaKuKr_9P8Kf7dnLEjA0Vf1OiaNjL_4qpGXNKCUh6mFDcE84rPeAIh5Jwa1b8ItNWqYd5sk3lj6q42sAVVMKc1y'
    code_challenge = 'DHyLc10oQmCmxyfNAAXPT29WHXjjTuXQOv6Egf0fzSI'

    def _test_token_pkce_ok(self, code_challenge, code_challenge_method, code_verifier):
        authorize_params = AuthorizationCodeTestCase.get_authorize_parameters(**{'code_challenge': code_challenge, 'code_challenge_method': code_challenge_method})
        response = self.do_code_token(authorize_params,
                                      self.get_token_request_parameters(**{'code_verifier': code_verifier}),
                                      self.get_default_headers())
        return response

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_token_s256_ok(self):
        response = self._test_token_pkce_ok(self.code_challenge, 'S256', self.code_verifier)
        self.assertAccessTokenOK(response, refresh_token=True, id_token=True)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_token_plain_ok(self):
        response = self._test_token_pkce_ok(self.code_challenge, 'S256', self.code_verifier)
        self.assertAccessTokenOK(response, refresh_token=True, id_token=True)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_token_missing_code_verifier(self):
        authorize_params = AuthorizationCodeTestCase.get_authorize_parameters(**{'code_challenge': self.code_challenge,
                                                                                 'code_challenge_method': 'S256'})
        response = self.do_code_token(authorize_params,
                                      self.get_token_request_parameters(),
                                      self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Code verifier required.')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_token_wrong_code_challenge_lenght(self):
        authorize_params = AuthorizationCodeTestCase.get_authorize_parameters(**{'code_challenge': self.code_challenge,
                                                                                 'code_challenge_method': 'S256'})
        response = self.do_code_token(authorize_params,
                                      self.get_token_request_parameters(**{'code_verifier': 'foo'}),
                                      self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_grant')

    @freeze_time(datetime.utcnow(), tz_offset=0)
    def test_token_wrong_code_verifier(self):
        authorize_params = AuthorizationCodeTestCase.get_authorize_parameters(**{'code_challenge': self.code_challenge,
                                                                                 'code_challenge_method': 'S256'})
        response = self.do_code_token(authorize_params,
                                      self.get_token_request_parameters(**{'code_verifier': 'foo'}),
                                      self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_grant')


@override_settings(ACCESS_TOKEN_TTL=100, REFRESH_TOKEN_TTL=200)
class AuthorizationCodeTTLTestCase(AuthorizationCodeTokenTestCase):

    def do_ttl_token(self):
        token, _ = self._test_token_ok(AuthorizationCodeTestCase.get_authorize_parameters(), self.get_token_request_parameters(), self.get_default_headers())
        return token, TokenCollection.objects.find_one({'access_token': token['access_token'], 'refresh_token': token['refresh_token']})

    def test_default_config(self):
        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 100)
        self.assertEqual(dbtoken['access_token_ttl'], 100)
        self.assertEqual(dbtoken['refresh_token_ttl'], 200)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 100)
        self.assertEqual(int((dbtoken['refresh_token_expires_at'] - dbtoken['creation']).total_seconds()), 200)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'client_credentials': 202, 'urn:openid:params:grant-type:ciba': 203, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 204},
                       REFRESH_TOKEN_TTL_BY_GRANT={'client_credentials': 402, 'urn:openid:params:grant-type:ciba': 403, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 404})
    def test_no_grant_config(self):
        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 100)
        self.assertEqual(dbtoken['access_token_ttl'], 100)
        self.assertEqual(dbtoken['refresh_token_ttl'], 200)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 100)
        self.assertEqual(int((dbtoken['refresh_token_expires_at'] - dbtoken['creation']).total_seconds()), 200)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'authorization_code': 201, 'client_credentials': 202, 'urn:openid:params:grant-type:ciba': 203, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 204},
                       REFRESH_TOKEN_TTL_BY_GRANT={'authorization_code': 401, 'client_credentials': 402, 'urn:openid:params:grant-type:ciba': 403, 'urn:ietf:params:oauth:grant-type:jwt-bearer': 404})
    def test_grant_config(self):
        token, dbtoken = self.do_ttl_token()
        self.assertEqual(token['expires_in'], 201)
        self.assertEqual(dbtoken['access_token_ttl'], 201)
        self.assertEqual(dbtoken['refresh_token_ttl'], 401)
        self.assertEqual(int((dbtoken['expires_at'] - dbtoken['creation']).total_seconds()), 201)
        self.assertEqual(int((dbtoken['refresh_token_expires_at'] - dbtoken['creation']).total_seconds()), 401)

    @override_settings(ACCESS_TOKEN_TTL_BY_GRANT={'authorization_code': 201},
                       REFRESH_TOKEN_TTL_BY_GRANT={'authorization_code': 401})
    def test_client_config(self):
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
                            'grant_type': 'authorization_code',
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
