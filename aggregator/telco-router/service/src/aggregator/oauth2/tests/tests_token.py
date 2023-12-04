import hashlib
import time
from base64 import urlsafe_b64encode
from datetime import datetime
from datetime import timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.test.client import Client
from freezegun.api import datetime_to_fakedatetime, FakeDatetime
from jsonschema import FormatChecker
from jsonschema.validators import Draft7Validator
from jwcrypto.jws import JWS

from aggregator.oauth2.tests.tests_basic import APPLICATION, BasicTestCase
from aggregator.utils.jwk import JWKManager
from aggregator.utils.jws import get_jws_info
from aggregator.utils.utils import overwrite_dict

JWT_ID_TOKEN_PAYLOAD = {
    'type': 'object',
    'properties': {
        'nonce': {
            'type': 'string'
        },
        'aud': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'iss': {
            'type': 'string'
        },
        'exp': {
            'type': 'integer',
        },
        'iat': {
            'type': 'integer',
        },
        'sub': {
            'type': 'string'
        },
        'azp': {
            'type': 'string'
        },
        'acr': {
            'type': 'string'
        },
        'amr': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'auth_time': {
            'type': 'integer',
        },
        'phone_number': {
            'type': 'string',
            'pattern': r'^\+\d+$'
        }
    },
    'required': ['aud', 'iss', 'exp', 'iat', 'sub', 'azp', 'acr', 'amr'],
    'additionalProperties': False
}

JWT_ID_TOKEN_VALIDATOR = Draft7Validator(JWT_ID_TOKEN_PAYLOAD, format_checker=FormatChecker())


JWT_ACCESS_TOKEN_PAYLOAD = {
    'type': 'object',
    'properties': {
        'aud': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'iss': {
            'type': 'string'
        },
        'exp': {
            'type': 'integer',
        },
        'iat': {
            'type': 'integer',
        },
        'jti': {
            'type': 'string',
        },
        'client_id': {
            'type': 'string',
        },
        'scopes': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'sub': {
            'type': 'string'
        },
        'uid': {
            'type': 'string'
        },
        'acr': {
            'type': 'string'
        },
        'amr': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'auth_time': {
            'type': 'integer',
        }
    },
    'required': ['aud', 'iss', 'exp', 'iat', 'jti', 'scopes', 'client_id'],
    'additionalProperties': False
}

JWT_ACCESS_TOKEN_VALIDATOR = Draft7Validator(JWT_ACCESS_TOKEN_PAYLOAD, format_checker=FormatChecker())

ACCESS_TOKEN_PAYLOAD = {
    'type': 'object',
    'properties': {
        'access_token': {
            'type': 'string'
        },
        'token_type': {
            'type': 'string',
            'enum': ['Bearer']
        },
        'refresh_token': {
            'type': 'string'
        },
        'expires_in': {
            'type': 'integer'
        },
        'scope': {
            'type': 'string'
        },
        'id_token': {
            'type': 'string'
        },
        'correlation_id': {
            'type': 'string'
        },
        'auth_req_id': {
            'type': 'string'
        }
    },
    'required': ['access_token', 'expires_in', 'scope'],
    'additionalProperties': False
}

ACCESS_TOKEN_VALIDATOR = Draft7Validator(ACCESS_TOKEN_PAYLOAD, format_checker=FormatChecker())


class TokenTestCase(BasicTestCase):

    @classmethod
    def get_db_token(cls, **kwargs):
        now = datetime.utcnow()
        now = now.replace(microsecond=now.microsecond - now.microsecond % 1000)
        token = {
            'access_token': '7eB6bgCzdyFRZKXWpP8SdBQRvdOlO8',
            'scopes': ['openid', 'phone'],
            'access_token_ttl': settings.ACCESS_TOKEN_TTL,
            'expires_at': now + timedelta(seconds=settings.ACCESS_TOKEN_TTL),
            'creation': now,
            'client_id': APPLICATION['_id'],
            'client_name': 'Foo',
            'grant_type': 'authorization_code',
            'type': 'Bearer',
            'consent_date': now.replace(microsecond=0),
            'sub': '2128c01f-dcc8-4fde-a74e-eba2f9b1a3af',
            'uid': 'tel:+34618051526',
            'claims': {},
            'id_token': 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHRLaWQifQ.eyJhY3IiOiIyIiwiYW1yIjpbIlNNU19VUkxfT0siXSwiYXRfaGFzaCI6ImNNcUFZZWNxclAzZE9uam1YQ0Fna2ciLCJhdWQiOlsiZmNjZTYyMDgtMmE1Mi00Y2JkLTgzODctMGJiMGFhMGQ0NzgxIl0sImF6cCI6ImZjY2U2MjA4LTJhNTItNGNiZC04Mzg3LTBiYjBhYTBkNDc4MSIsImV4cCI6MTU4MjA5Njg1NCwiaGFzaGVkX2xvZ2luX2hpbnQiOiI1WjlQbEN4bmNaQW1kWm9RQ21kMEdKZm4zTzluVExFanhxUjhRNU1QVHRRIiwiaWF0IjoxNTgyMDk2NTU0LCJpc3MiOiJodHRwczovL2Rldi5tb2JpbGVjb25uZWN0LnBkaS50aWQuZXMvZXMvb2F1dGgyL2F1dGhvcml6ZSIsIm5vbmNlIjoiOTJlNTkzNjEtYzEyZC00NTIzLWExOWMtMGU4NzAwNTM5YWFlIiwic3ViIjoiMjEyOGMwMWYtZGNjOC00ZmRlLWE3NGUtZWJhMmY5YjFhM2FmIn0.3YvQOSVIZBinO72ibDnVzbUQglWvpaWZPtAagddTNjDlrge-KWqa6KKFOev8JH-5g8MLOct-Cm7MDz804hIPYKEb4Q2VhqKn4pzpSW_mW0LWVmiAz6v-S1-HrmR5OHomkeK7DH76saP7cxX25WD11f7DkA6Dc969UBHqhauiYIpHQ-gjHmyWWOC5gLisGm4fk2fcfEGZsVvk-qosV6uaKu3OWNtaO8DMO6SFRBKKLHKGpg8OryR8OBqAYWZtoyR5dWGUk3gKhkuo6Evl1TiEPEF0VdGWlGYh6nMVmAhZ-JMtg0SjpN9ZmN_74ge7KXbZY1MZU4IljuFaVlJY0frdik6HfNKkUs876c7WxgtFzAdN_kcEkXzuzr0y0kjeIvJrCPN3PoiLMqP_5b33Jyyq5HVGgs-m4sammJxIlJ4dK1SDHjWi0rXJyWyFGk4sutA3Pa_iksRZ1dWf8bzbAWBRiQXpz25rSFI57iz9PL0ksr90blaGsq7zvQumfu6uKR8oC7DCXhQJkhoMoCm0qxx_D3J-5B2w3hCa7ooiI4qxIYIFAe_QSWM_JjY9U9cMCVT2O9WnPtXG-c2hd8m3gKx6L7Iqm4xICwGub_Y8RFwsyz6M1BEXW8fD5fb4kvenxlgYRGXw7_u_0SirQ4py9EVbkTsk4lbqNla1yEUIf7yDGso',
            'refresh_token': 'dNKEPRR4j3CFpwSFOslmzODFjY9XaH',
            'refresh_token_ttl': settings.REFRESH_TOKEN_TTL,
            'refresh_token_expires_at': now + timedelta(seconds=settings.REFRESH_TOKEN_TTL),
            'expiration': max([now + timedelta(seconds=settings.REFRESH_TOKEN_TTL), now + timedelta(seconds=settings.ACCESS_TOKEN_TTL)])
        }

        overwrite_dict(token, kwargs)

        return token

    @classmethod
    def get_id_token(cls, **kwargs):
        now = int(time.time())
        id_token = {
            'acr': '2',
            'amr': ['nbma'],
            'nonce': '70979686-e99a-4dc9-a668-b76c5bbf9ae0',
            'sub': '2128c01f-dcc8-4fde-a74e-eba2f9b1a3af',
            'auth_time': now,
            'iat': now,
            'exp': now + 300,
            'aud': ['68399c5b-3cfa-4348-9f96-33d379077d71'],
            'azp': '68399c5b-3cfa-4348-9f96-33d379077d71',
            'iss': settings.AGGREGATOR_HOST
        }

        overwrite_dict(id_token, kwargs)
        return id_token

    @classmethod
    def get_jwt_data(cls, jwt, validator):
        jwstoken = JWS()
        jwstoken.deserialize(jwt)
        signature_key = JWKManager().get_public_key()
        token_data = get_jws_info(jwstoken, signature_key, settings.AGGREGATOR_ISSUER, [APPLICATION['_id']], validator).payload
        return token_data

    @classmethod
    def get_id_token_data(cls, id_token):
        return cls.get_jwt_data(id_token, JWT_ID_TOKEN_VALIDATOR)

    @classmethod
    def get_access_token_data(cls, access_token):
        return cls.get_jwt_data(access_token, JWT_ACCESS_TOKEN_VALIDATOR)

    @classmethod
    def do_token(cls, payload, headers, **kwargs):
        client = Client()
        return client.post('/oauth2/token', data=urlencode(payload), content_type='application/x-www-form-urlencoded', **headers)

    def assertHash(self, value_to_hash, hashed_value):
        _hash = hashlib.sha256()
        _hash.update(value_to_hash.encode('ascii'))
        digest = _hash.digest()
        truncated = digest[:int(len(digest) / 2)]
        self.assertEqual(urlsafe_b64encode(truncated).decode('utf-8').rstrip('='), hashed_value)

    def assertAccessTokenOK(self, response, refresh_token=True, id_token=True):
        self.assertEqual(response.status_code, 200)
        token = response.json()

        try:
            ACCESS_TOKEN_VALIDATOR.validate(token)
        except Exception as e:
            self.fail('Schema failed: %s' % str(e.args[0]))

        if refresh_token:
            self.assertIn('refresh_token', token)
        else:
            self.assertNotIn('refresh_token', token)

        if id_token:
            self.assertIn('id_token', token)
            id_token_str = token['id_token']
            id_token_data = self.get_id_token_data(id_token_str)

            self.assertEqual(id_token_data['iss'], settings.AGGREGATOR_ISSUER)
            self.assertEqual(id_token_data['aud'], [APPLICATION['_id']])
            self.assertEqual(id_token_data['sub'], '2128c01f-dcc8-4fde-a74e-eba2f9b1a3af')
        else:
            self.assertNotIn('id_token', token)

        return token

    def assertAccessTokenError(self, response, status, **kwargs):
        self.assertEqual(response.status_code, status)
        body = {
            "error": "access_denied",
            "error_description": "user cancelled",
            "correlation_id": "b41d03ca-67bb-43db-8384-e6e5d2404988"
        }

        overwrite_dict(body, kwargs)

        self.assertDictEqual(body, response.json())

    def assertDbTokenEqual(self, dbtoken, values):
        if '_id' in dbtoken:
            del dbtoken['_id']
        dbtoken_fake = {k: datetime_to_fakedatetime(v) if k in values and isinstance(values[k], FakeDatetime) else v for k, v in dbtoken.items()}
        self.assertDictEqual(dbtoken_fake, values)


class TokenErrorTestCase(TokenTestCase):

    def test_wrong_method(self):
        client = Client()
        response = client.get('/oauth2/token')
        self.assertEqual(response.status_code, 405)
