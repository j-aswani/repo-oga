from jsonschema import FormatChecker
from jsonschema.validators import Draft7Validator

FIELD_NONCE = 'nonce'
FIELD_AUDIENCE = 'aud'
FIELD_ISSUER = 'iss'
FIELD_ACR_VALUES = 'acr_values'
FIELD_REDIRECT_URI = 'redirect_uri'
FIELD_CLIENT_ID = 'client_id'
FIELD_CLIENT_NAME = 'client_name'
FIELD_PROMPT = 'prompt'
FIELD_LOGIN_HINT = 'login_hint'
FIELD_SCOPES = 'scopes'
FIELD_SCOPE = 'scope'
FIELD_CLAIMS = 'claims'
FIELD_MAX_AGE = 'max_age'
FIELD_EXPIRATION = 'exp'
FIELD_ISSUED_TIME = 'iat'
FIELD_NOT_BEFORE = 'nbf'
FIELD_CORRELATOR = 'corr'
FIELD_ACR = 'acr'
FIELD_AMR = 'amr'
FIELD_AUTH_TIME = 'auth_time'
FIELD_SUB = 'sub'
FIELD_UID = 'uid'
FIELD_ERROR = 'error'
FIELD_ERROR_DESCRIPTION = 'error_description'
FIELD_CLAIM_PHONE = 'phone_number'
FIELD_IDENTIFIER_TYPE = 'identifier_type'
FIELD_IDENTIFIER = 'identifier'

FIELD_ALG = 'alg'
FIELD_KID = 'kid'


JWT_ID_TOKEN_PAYLOAD = {
    'type': 'object',
    'properties': {
        FIELD_SUB: {
            'type': 'string'
        },
        FIELD_NONCE: {
            'type': 'string'
        },
        FIELD_AUDIENCE: {
            "anyOf": [
                {'type': 'string'},
                {'type': 'array', 'items': {'type': 'string'}}
            ]
        },
        FIELD_ISSUER: {
            'type': 'string'
        },
        FIELD_EXPIRATION: {
            'type': 'integer',
        },
        FIELD_ISSUED_TIME: {
            'type': 'integer',
        },
        FIELD_ACR: {
            'type': 'string'
        },
        FIELD_AMR: {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
    },
    'required': [FIELD_SUB, FIELD_NONCE, FIELD_AUDIENCE, FIELD_ISSUER, FIELD_EXPIRATION, FIELD_ISSUED_TIME, FIELD_ACR, FIELD_AMR],
    'additionalProperties': True
}

JWT_ID_TOKEN_VALIDATOR = Draft7Validator(JWT_ID_TOKEN_PAYLOAD, format_checker=FormatChecker())

FIELD_JTI = 'jti'

JWT_CLIENT_ASSERTION_PAYLOAD = {
    'type': 'object',
    'properties': {
        FIELD_AUDIENCE: {
            "anyOf": [
                {'type': 'string'},
                {'type': 'array', 'items': {'type': 'string'}}
            ]
        },
        FIELD_ISSUER: {
            'type': 'string'
        },
        FIELD_EXPIRATION: {
            'type': 'integer',
        },
        FIELD_ISSUED_TIME: {
            'type': 'integer',
        },
        FIELD_NOT_BEFORE: {
            'type': 'integer',
        },
        FIELD_SUB: {
            'type': 'string',
        },
        FIELD_JTI: {
            'type': 'string'
        },
    },
    'required': [FIELD_ISSUER, FIELD_AUDIENCE, FIELD_EXPIRATION, FIELD_ISSUED_TIME, FIELD_SUB, FIELD_JTI],
    'additionalProperties': False
}

JWT_CLIENT_ASSERTION_VALIDATOR = Draft7Validator(JWT_CLIENT_ASSERTION_PAYLOAD, format_checker=FormatChecker())

JWT_ASSERTION_PAYLOAD = {
    'type': 'object',
    'properties': {
        FIELD_AUDIENCE: {
            "anyOf": [
                {'type': 'string'},
                {'type': 'array', 'items': {'type': 'string'}}
            ]
        },
        FIELD_ISSUER: {
            'type': 'string'
        },
        FIELD_EXPIRATION: {
            'type': 'integer',
        },
        FIELD_ISSUED_TIME: {
            'type': 'integer',
        },
        FIELD_NOT_BEFORE: {
            'type': 'integer',
        },
        FIELD_SUB: {
            'type': 'string',
        },
        FIELD_JTI: {
            'type': 'string'
        },
        FIELD_UID: {
            'type': 'string'
        },
        FIELD_ACR: {
            'type': 'string'
        },
        FIELD_AMR: {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        FIELD_AUTH_TIME: {
            'type': 'integer'
        },
        FIELD_SCOPE: {
            'type': 'string'
        }
    },
    'required': [FIELD_ISSUER, FIELD_AUDIENCE, FIELD_EXPIRATION, FIELD_ISSUED_TIME, FIELD_SUB],
    'additionalProperties': True
}

JWT_ASSERTION_VALIDATOR = Draft7Validator(JWT_ASSERTION_PAYLOAD, format_checker=FormatChecker())


JWT_LOGIN_HINT_TOKEN_PAYLOAD = {
    'type': 'object',
    'properties': {
        FIELD_AUDIENCE: {
            "anyOf": [
                {'type': 'string'},
                {'type': 'array', 'items': {'type': 'string'}}
            ]
        },
        FIELD_ISSUER: {
            'type': 'string'
        },
        FIELD_EXPIRATION: {
            'type': 'integer',
        },
        FIELD_ISSUED_TIME: {
            'type': 'integer',
        },
        FIELD_NOT_BEFORE: {
            'type': 'integer',
        },
        FIELD_JTI: {
            'type': 'string'
        },
        FIELD_IDENTIFIER_TYPE: {
            'type': 'string',
            "enum": ["phone_number", "ip"]
        },
        FIELD_IDENTIFIER: {
            'type': 'string'
        }
    },
    'required': [FIELD_ISSUER, FIELD_AUDIENCE, FIELD_EXPIRATION, FIELD_ISSUED_TIME, FIELD_JTI, FIELD_IDENTIFIER_TYPE, FIELD_IDENTIFIER],
    'additionalProperties': True
}

JWT_LOGIN_HINT_TOKEN_VALIDATOR = Draft7Validator(JWT_LOGIN_HINT_TOKEN_PAYLOAD, format_checker=FormatChecker())
