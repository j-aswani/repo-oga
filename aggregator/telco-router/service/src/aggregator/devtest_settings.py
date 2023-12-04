import os

try:
    from .settings import *
except ImportError:
    pass

MONGO_DATABASE_OPTIONS = {
    'default': {
        'host': 'mongodb://localhost:27017/aggregator-telcorouter-test'
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'aggregator',
        'TIMEOUT': 0
    }
}

DEBUG = False

LANGUAGE_CODE = 'en'
LANGUAGES = [('en', 'English')]

AUTHORIZATION_CODE_TTL = 300
ACCESS_TOKEN_TTL = 600
ACCESS_TOKEN_TTL_BY_GRANT = {}

TELCO_FINDER_HOST = "http://api.aggregator.com"

SP_JWT_SIGNING_ALGORITHM = 'RS256'
SP_JWT_PRIVATE_KEY_FILE = os.path.join(os.path.dirname(__file__), 'tests/keys/sp_jwtRS256_private.pem')
SP_JWT_PRIVATE_KEY_PASSWORD = None
SP_JWT_PUBLIC_KEY_FILE = os.path.join(os.path.dirname(__file__), 'tests/keys/sp_jwtRS256_public.pem')
SP_JWT_KID = 'sp_kid'

OPERATOR_JWT_SIGNING_ALGORITHM = 'RS256'
OPERATOR_JWT_PRIVATE_KEY_FILE = os.path.join(os.path.dirname(__file__), 'tests/keys/operator_jwtRS256_private.pem')
OPERATOR_JWT_PRIVATE_KEY_PASSWORD = None
OPERATOR_JWT_PUBLIC_KEY_FILE = os.path.join(os.path.dirname(__file__), 'tests/keys/operator_jwtRS256_public.pem')
OPERATOR_JWT_KID = 'operator_kid'
