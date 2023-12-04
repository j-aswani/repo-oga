from django.test.client import Client
from jsonschema import FormatChecker
from jsonschema.validators import validate

from aggregator.oauth2.tests.tests_basic import BasicTestCase

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

