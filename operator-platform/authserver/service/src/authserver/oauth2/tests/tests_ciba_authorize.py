import json
import time
from datetime import datetime
from urllib.parse import urlencode
from uuid import uuid4

import requests_mock
from django.conf import settings
from django.core.cache import cache
from django.test.client import Client
from freezegun import freeze_time
from jsonschema import FormatChecker
from jsonschema.validators import Draft7Validator

from authserver.oauth2.models import CibaAuthorizationCollection, ApplicationCollection, UserPcrCollection
from authserver.oauth2.tests.tests_basic import BasicTestCase, APPLICATION, USER_PCR, SP_JWT_PRIVATE_KEY, get_signed_jwt, get_unsigned_jwt
from authserver.utils.jwk import JWKManager
from authserver.utils.utils import overwrite_dict

POLLING_PAYLOAD = {
    'type': 'object',
    'properties': {
        'expires_in': {
            'type': 'integer'
        },
        'interval': {
            'type': 'integer',
        },
        'auth_req_id': {
            'type': 'string'
        }
    },
    'required': ['auth_req_id', 'expires_in'],
    'additionalProperties': False
}

POLLING_PAYLOAD_VALIDATOR = Draft7Validator(POLLING_PAYLOAD, format_checker=FormatChecker())


class CibaTestCase(BasicTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION)
        UserPcrCollection.objects.insert_one(USER_PCR)
        cache.clear()

    @classmethod
    def do_mocking(cls, m, jwks_uri_params=None, uq_params=None):
        super(CibaTestCase, cls).do_mocking(m, jwks_uri_params=jwks_uri_params)
        m.get('https://www.foo.bar/.well-known/openid-configuration',
              text=json.dumps({'jwks_uri': APPLICATION["jwks_uri"]}))

    @classmethod
    def do_authorize(cls, payload, headers, **kwargs):
        client = Client()
        return client.post('/oauth2/bc-authorize', data=urlencode(payload), content_type='application/x-www-form-urlencoded', **headers)

    @classmethod
    def get_authorization_request(cls):
        response = CibaTestCase.do_authorize(cls.get_authorize_parameters()[0], cls.get_default_headers())
        return CibaAuthorizationCollection.objects.find_one({'_id': response.json()['auth_req_id']})

    def assertAuthorizeOK(self, response):
        self.assertEqual(response.status_code, 200)
        payload = response.json()

        try:
            POLLING_PAYLOAD_VALIDATOR.validate(payload)
        except Exception as e:
            self.fail('Schema failed: %s' % str(e.args[0]))

        return payload['auth_req_id']

    @classmethod
    def get_authorize_parameters(cls, **kwargs):
        params = {
            'scope': 'openid phone'
        }

        now = time.time()
        login_hint_token_params = {
            'identifier_type': 'phone_number',
            'identifier': '+34618051526',
            'iss': 'https://www.foo.bar',
            'aud': f'{settings.AUTHSERVER_HOST}',
            'jti': str(uuid4()),
            'iat': int(now),
            'exp': int(now) + 300,
        }

        overwrite_dict(login_hint_token_params, kwargs)

        params['login_hint_token'] = get_signed_jwt(login_hint_token_params, settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)

        overwrite_dict(params, kwargs)

        return params, login_hint_token_params


class CibaOKTestCase(CibaTestCase):

    def _test_ok(self):
        params, _ = self.get_authorize_parameters()
        response = self.do_authorize(params, self.get_default_headers())
        self.assertAuthorizeOK(response)
        return response

    @requests_mock.mock()
    def test_authorize_delegated_consent_ok(self, m):
        self.do_mocking(m)
        self._test_ok()

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_authorize_ok_client_secret_post(self, m):
        self.do_mocking(m)
        params, _ = self.get_authorize_parameters()
        params['client_id'] = APPLICATION['_id']
        params['client_secret'] = APPLICATION['consumer_secret']
        response = self.do_authorize(params, {})
        self.assertAuthorizeOK(response)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_authorize_ok_jwt_bearer(self, m):
        self.do_mocking(m)
        params, _ = self.get_authorize_parameters()
        params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        params['client_assertion'] = get_signed_jwt(self.get_default_client_assertion(), settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, SP_JWT_PRIVATE_KEY)
        response = self.do_authorize(params, {})
        self.assertAuthorizeOK(response)

    @freeze_time(datetime.utcnow(), tz_offset=0)
    @requests_mock.mock()
    def test_login_hint(self, m):
        self.do_mocking(m)
        params, _ = self.get_authorize_parameters(**{'login_hint_token': None, 'login_hint': 'tel:+34618051526'})
        response = self.do_authorize(params, self.get_default_headers())
        self.assertAuthorizeOK(response)


class CibaErrorTestCase(CibaTestCase):

    @requests_mock.mock()
    def test_invalid_grant(self, m):
        self.do_mocking(m)

        ApplicationCollection.objects.update_one(
            {'_id': APPLICATION['_id']},
            {
                '$set': {
                    'grants': [
                        {
                            'grant_type': 'authorization_code',
                            'scopes': [
                                'openid',
                                'phone'
                            ],
                            'claims': [
                                '/id_token/phone_number'
                            ]
                        }
                    ]
                }
            }
        )

        response = self.do_authorize(self.get_authorize_parameters()[0], self.get_default_headers())
        self.assertJsonError(response, 400, 'unauthorized_client')

    def test_duplicated_parameters(self):
        client = Client()
        for param in ['scope', 'login_hint_token']:
            response = client.post('/oauth2/bc-authorize',
                                   data=f'{param}=foo&{param}=bar', content_type='application/x-www-form-urlencoded', **self.get_default_headers())
            self.assertJsonError(response, 400, 'invalid_request', f'Duplicate {param} parameter.')

    @requests_mock.mock()
    def test_missing_hint(self, m):
        self.do_mocking(m)

        response = self.do_authorize(self.get_authorize_parameters(**{'login_hint_token': None})[0],
                                     self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', f'Missing hint parameter.')

    @requests_mock.mock()
    def test_invalid_scope(self, m):
        self.do_mocking(m)

        response = self.do_authorize(self.get_authorize_parameters(**{'scope': 'openid wrong'})[0],
                                     self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_scope')

    @requests_mock.mock()
    def test_multiple_hint(self, m):
        self.do_mocking(m)

        response = self.do_authorize(self.get_authorize_parameters(**{'login_hint': 'tel:+34618051526'})[0],
                                     self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request',  "Multiple authorization hint.")


class CibaLoginHintTokenErrorTestCase(CibaTestCase):

    @requests_mock.mock()
    def test_unavailable_jwks_uri(self, m):
        self.do_mocking(m, jwks_uri_params={'status_code': 404, 'text': ''})

        response = self.do_authorize(self.get_authorize_parameters()[0], self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid login_hint_token (Unavailable signature key.).')

    @requests_mock.mock()
    def test_invalid_kid(self, m):
        self.do_mocking(m)

        params, login_hint_token_params = self.get_authorize_parameters()
        params['login_hint_token'] = get_signed_jwt(login_hint_token_params, settings.SP_JWT_SIGNING_ALGORITHM, 'wrong', SP_JWT_PRIVATE_KEY)
        response = self.do_authorize(params, self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid login_hint_token (Unavailable signature key.).')

    def test_unsigned_request_object(self):
        params, login_hint_token_params = self.get_authorize_parameters()
        params['login_hint_token'] = get_unsigned_jwt(login_hint_token_params)
        response = self.do_authorize(params, self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid login_hint_token (Invalid JWT: Invalid alg value.).')

    @requests_mock.mock()
    def test_invalid_signature(self, m):
        self.do_mocking(m)

        params, login_hint_token_params = self.get_authorize_parameters()
        params['login_hint_token'] = get_signed_jwt(login_hint_token_params, settings.SP_JWT_SIGNING_ALGORITHM, settings.SP_JWT_KID, JWKManager().get_private_key())
        response = self.do_authorize(params, self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid login_hint_token (Invalid signature.).')

    @requests_mock.mock()
    def test_expired_jwt(self, m):
        self.do_mocking(m)

        response = self.do_authorize(self.get_authorize_parameters(**{'exp': int(time.time() - 100)})[0],
                                     self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid login_hint_token (Invalid JWT: Expired JWT.).')

    @requests_mock.mock()
    def test_jwt_from_future(self, m):
        self.do_mocking(m)

        response = self.do_authorize(self.get_authorize_parameters(**{'iat': int(time.time() + 100)})[0],
                                     self.get_default_headers())
        self.assertJsonError(response, 400, 'invalid_request', 'Invalid login_hint_token (Invalid JWT: JWT comes from future.).')


    @requests_mock.mock()
    def test_missing_login_hint_token_parameters(self, m):
        self.do_mocking(m)

        for param in ['identifier_type', 'identifier']:
            params, _ = self.get_authorize_parameters(**{param: None})
            response = self.do_authorize(params, self.get_default_headers())
            self.assertJsonError(response, 400, 'invalid_request', f"Invalid login_hint_token ('{param}' is a required property).")

    @requests_mock.mock()
    def test_mismatching_login_hint_token_parameters(self, m):
        self.do_mocking(m)

        tests = [
            ('identifier_type', 'wrong', "Invalid login_hint_token ('wrong' is not one of ['phone_number', 'ip'])."),
            ('identifier_type', 1, "Invalid login_hint_token (1 is not of type 'string').")
        ]

        for param, value, error in tests:
            params, _ = self.get_authorize_parameters(**{param: value})
            response = self.do_authorize(params, self.get_default_headers())
            self.assertJsonError(response, 400, 'invalid_request', error)

    @requests_mock.mock()
    def test_duplicated_jti(self, m):
        self.do_mocking(m)

        jti = str(uuid4())
        self.do_authorize(self.get_authorize_parameters(**{'jti': jti})[0],
                                     self.get_default_headers())

        response = self.do_authorize(self.get_authorize_parameters(**{'jti': jti})[0],
                                     self.get_default_headers())

        self.assertJsonError(response, 400, 'invalid_request', 'Invalid login_hint_token parameter value: jti parameter was already used.')
