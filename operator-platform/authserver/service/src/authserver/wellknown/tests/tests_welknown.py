from django.test.client import Client
from jsonschema import FormatChecker
from jsonschema.validators import validate

from authserver.oauth2.models import ApplicationCollection
from authserver.oauth2.tests.tests_basic import BasicTestCase, APPLICATION_BASIC

OIDC_CONFIGURATION_PAYLOAD = {
    'type': 'object',
    'properties': {
        'issuer': {
            'type': 'string'
        },
        'authorization_endpoint': {
            'type': 'string',
            'format': 'uri'
        },
        'revocation_endpoint': {
            'type': 'string',
            'format': 'uri'
        },
        'backchannel_authentication_endpoint': {
            'type': 'string',
            'format': 'uri'
        },
        'token_endpoint': {
            'type': 'string',
            'format': 'uri'
        },
        'introspection_endpoint': {
            'type': 'string',
            'format': 'uri'
        },
        'jwks_uri': {
            'type': 'string',
            'format': 'uri'
        },
        'userinfo_endpoint': {
            'type': 'string',
            'format': 'uri'
        },
        'grant_types_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'token_endpoint_auth_methods_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'introspection_endpoint_auth_methods_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'revocation_endpoint_auth_methods_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'subject_types_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'response_types_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'response_modes_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'code_challenge_methods_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'id_token_signing_alg_values_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'request_object_signing_alg_values_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'token_endpoint_auth_signing_alg_values_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'claims_parameter_supported': {
            'type': 'boolean'
        },
        'request_parameter_supported':  {
            'type': 'boolean'
        },
        'request_uri_parameter_supported':  {
            'type': 'boolean'
        },
        'claims_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'ui_locales_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'acr_values_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'scopes_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'login_hint_token_supported':  {
            'type': 'boolean'
        },
        'login_hint_types_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'backchannel_user_code_parameter_supported': {
            'type': 'boolean'
        },
        'backchannel_token_delivery_modes_supported': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        }
    },
    'required': [],
    'additionalProperties': False
}


WEBFINGER_PAYLOAD = {
    'type': 'object',
    'properties': {
        'subject': {
            'type': 'string'
        },
        'properties': {
            'type': 'object',
            'additionalProperties': {'type': 'string'}
        },
        'aliases': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'links': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'rel': {
                        'type': 'string'
                    },
                    'href': {
                        'type': 'string',
                        'format': 'uri'
                    },
                    'type': {
                        'type': 'string'
                    },
                    'titles': {
                        'type': 'object',
                        'additionalProperties': {'type': 'string'}
                    },
                    'properties': {
                        'type': 'object',
                        'additionalProperties': {'type': 'string'}
                    }
                },
                'required': ['rel', 'href']
            }
        }
    },
    'required': ['subject'],
    'additionalProperties': False
}


class OIDCConfiguration(BasicTestCase):

    @classmethod
    def do_oidc_configuration(cls):
        client = Client()
        return client.get('/.well-known/openid-configuration')

    def test_oidc_configuration(self):
        response = self.do_oidc_configuration()

        try:
            validate(response.json(), schema=OIDC_CONFIGURATION_PAYLOAD, format_checker=FormatChecker())
        except Exception as e:
            self.fail('Schema failed: %s' % str(e.args[0]))


class WebFingerTestCase(BasicTestCase):

    def setUp(self):
        super().setUp()
        ApplicationCollection.objects.insert_one(APPLICATION_BASIC)

    @classmethod
    def do_webfinger(cls, params):
        client = Client()
        headers = {
            'HTTP_AUTHORIZATION': cls.get_authorization_header('c7667901-8c4f-4d5b-8836-e50e5b80fa9b', 'd86f12d1-d7b4-4d95-8159-7e9c202b5fa7')
        }
        return client.get('/.well-known/webfinger', data=params, **headers)

    def test_webfinger(self):
        response = self.do_webfinger(params={'resource': 'ipport:127.0.0.1'})

        try:
            validate(response.json(), schema=WEBFINGER_PAYLOAD, format_checker=FormatChecker())
        except Exception as e:
            self.fail('Schema failed: %s' % str(e.args[0]))

    def test_no_authentication_header(self):
        client = Client()
        response = client.get('/.well-known/webfinger')
        self.assertJsonError(response, 401, 'invalid_client', 'Authentication credentials were not provided.')

    def test_wrong_authentication_header(self):
        client = Client()
        headers = {
            'HTTP_AUTHORIZATION': 'Foo'
        }
        response = client.get('/.well-known/webfinger', **headers)
        self.assertJsonError(response, 401, 'invalid_client', 'Authentication credentials were not provided.')

    def test_wrong_credentials(self):
        client = Client()
        for username, password in [('foo', 'd86f12d1-d7b4-4d95-8159-7e9c202b5fa7'),
                            ('c7667901-8c4f-4d5b-8836-e50e5b80fa9b', 'foo')]:

            headers = {
                'HTTP_AUTHORIZATION': self.get_authorization_header(username, password)
            }
            response = client.get('/.well-known/webfinger', **headers)
            self.assertJsonError(response, 401, 'invalid_client', 'Invalid username/password.')
