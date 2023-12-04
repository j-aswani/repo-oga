from django.test.client import Client
from jsonschema import FormatChecker
from jsonschema.validators import validate

from aggregator.oauth2.tests.tests_basic import BasicTestCase

JWT_DISCOVERY_PAYLOAD = {
    'type': 'object',
    'properties': {
        'issuer': {
            'type': 'string'
        },
        'token_endpoint': {
            'type': 'string',
            'format': 'uri'
        },
        'jwks_uri': {
            'type': 'string',
            'format': 'uri'
        },
        'grant_types_supported': {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        'token_endpoint_auth_methods_supported': {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        'code_challenge_methods_supported': {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        'token_endpoint_auth_signing_alg_values_supported': {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
        'scopes_supported': {
            "type": "array",
            "items": {
                "type": "string"
            }
        },
    },
    'required': [],
    'additionalProperties': True
}


class DiscoveryTestCase(BasicTestCase):

    @classmethod
    def do_discovery(cls):
        client = Client()
        return client.get('/oauth2/.well-known/openid-configuration')

    def test_discovery(self):
        response = self.do_discovery()

        try:
            validate(response.json(), schema=JWT_DISCOVERY_PAYLOAD, format_checker=FormatChecker())
        except Exception as e:
            self.fail('Schema failed: %s' % str(e.args[0]))
