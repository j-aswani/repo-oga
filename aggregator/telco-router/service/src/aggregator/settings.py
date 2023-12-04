import os
import sys

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = eval(os.getenv('DEBUG', "True").lower().title())

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'v(24-s_2m17w3iyxek^yecfvshn7$wwx3uf-03d-c079+j^x^w'

SILENCED_SYSTEM_CHECKS = ['urls.W002']

# Application definition

INSTALLED_APPS = [
    # 'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'aggregator.oauth2',
    'aggregator.wellknown',
    'aggregator.health'
]

MIDDLEWARE = [
    'aggregator.middleware.telcorouter.AggregatorMiddleware',
    'aggregator.middleware.log.LogMiddleware',
    'django.middleware.security.SecurityMiddleware',
    # 'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',
    # 'django.contrib.auth.middleware.AuthenticationMiddleware',
    # 'django.contrib.messages.middleware.MessageMiddleware',
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.locale.LocaleMiddleware',
]

ROOT_URLCONF = 'aggregator.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(os.path.dirname(__file__), 'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'aggregator.utils.context_processors.branding',
            ],
        },
    },
]

WSGI_APPLICATION = 'aggregator.wsgi.application'

DATABASES = {}

MONGO_DATABASE_OPTIONS = {
    'default': {
        'host': f"mongodb://{os.getenv('DATABASE_HOST', 'localhost:27017')}/{os.getenv('DATABASE_NAME', 'aggregator-telcorouter')}",
        'socketTimeoutMS': 30000
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'aggregator',
        'TIMEOUT': 600
    }
}

# Internationalization

LANGUAGE_CODE = 'en-GB'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

LANGUAGES = [
    ('en', 'English'),
]

LOCALE_PATHS = [
    os.path.join(os.path.dirname(__file__), 'locale'),
]

STATICFILES_DIRS = [
    os.path.join(os.path.dirname(__file__), 'static'),
]

ALLOWED_HOSTS = ['*']

USE_X_FORWARDED_HOST = True
USE_X_FORWARDED_PORT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_NAME = 'aggregatorid'
CSRF_COOKIE_NAME = 'aggregatorcsrftoken'
CSRF_COOKIE_SECURE = True

AUTHENTICATION_BACKENDS = []

REST_FRAMEWORK = {
    'EXCEPTION_HANDLER': 'aggregator.utils.exceptions.api_exception_handler'
}

CENSORER_MASKED_FIELDS = {"csrfmiddlewaretoken", "Cookie"}
CENSORER_FULL_MASKED_FIELDS = set([])
CENSORER_MASK = '----'
CENSORER_NUM_UNMASKED_CHARS = 4

LOGGING_ROOT = os.environ.get('LOGS_ROOT', os.path.join(os.path.dirname(__file__), 'logs'))
LOGGING_PREFIX = 'telcorouter'
LOGGING_LEVEL = 'DEBUG' if DEBUG else 'INFO'
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s - %(asctime)s - %(module)s - %(process)d - %(thread)d - %(message)s'
        },
        'simple': {
            'format': '%(levelname)s - %(asctime)s - %(message)s'
        },
        'aggregator': {
            'format': '{"time":"%(UTCTimestamp)s","lvl":"%(levelname)s","corr":"%(correlator)s","trans":"%(transactionId)s","clientId":"%(clientId)s","user":"%(user)s","msg":"%(message)s","data":%(jsonMsg)s}'
        }
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        },
        'aggregator_fields': {
            '()': 'aggregator.utils.logger.LoggerFilter'
        }
    },
    'handlers': {
        'file': {  # define and name a handler
            'level': LOGGING_LEVEL,
            'filters': ['aggregator_fields'],
            'class': 'logging.FileHandler',  # set the logging class to log to a file
            'formatter': 'aggregator',  # define the formatter to associate
            'filename': os.path.join(LOGGING_ROOT, LOGGING_PREFIX + '.log')  # log file
        },
        'console': {
            'level': LOGGING_LEVEL,
            'filters': ['aggregator_fields'],
            'class': 'logging.StreamHandler',
            'formatter': 'aggregator',
            'stream': sys.stdout
        }
    },
    'loggers': {
        LOGGING_PREFIX: {
            'handlers': ['console'],
            'level': LOGGING_LEVEL,
            'propagate': False,
        }
    }
}
LOGGING_IGNORE_PATHS = set(['/health/check'])
LOGGING_SHOW_RESPONSE_VIEW_NAMES = set([])

COMPONENT = 'AGGREGATOR'

BRANDING = os.getenv('OPERATOR_ID', None)

AGGREGATOR_HOST = os.getenv('HOST', 'http://127.0.0.1:10010')
AGGREGATOR_ISSUER = AGGREGATOR_HOST
AGGREGATOR_KID = 'telcorouter'
AGGREGATOR_JWKS_URI = None
AGGREGATOR_AUDIENCES = [AGGREGATOR_ISSUER]

STATIC_URL = '/aggregator/static/'
STATIC_VERSION = '1.0.0'

# ERROR_DESCRIPTION_FORMAT values: lowercase or phrase
ERROR_DESCRIPTION_FORMAT = 'phrase'

ACCESS_TOKEN_TTL = 600
ACCESS_TOKEN_TTL_BY_GRANT = {}
AUTH_REQUEST_JWT_TTL = 600
AUTH_REQUEST_JWT_TIME_LEEWAY = 5

JWT_SIGNING_ALGORITHM = 'RS256'
JWT_PRIVATE_KEY_FILE = os.path.join(os.path.dirname(__file__), 'tests/keys/jwtRS256_private.pem')
JWT_PRIVATE_KEY_PASSWORD = 'mobileconnect'
JWT_PUBLIC_KEY_FILE = os.path.join(os.path.dirname(__file__), 'tests/keys/jwtRS256_public.pem')
JWT_KID = 'defaultKid'
JWT_TTL = 300

SECRET_KEYS = [
    {"kid": "aggregator", "kty": "oct", "k": "TwJ9u5HQLMC30olPhggKWSuTQ10vZCq7OkG8yDpKMH0"}
]

JWE_ACCESS_TOKEN_KID = "aggregator"

OIDC_DISCOVERY_PATH = '/.well-known/openid-configuration'
OIDC_VERIFY_CERTIFICATE = True
OIDC_DATA_TTL = 15 * 60  # in seconds
OIDC_HTTP_TIMEOUT = 10  # in seconds
AUTHORIZATION_CODE_TTL = 10 * 60  # in seconds
STATE_TTL = 15 * 60  # in seconds

JWKS_URI_TTL = 900
JWKS_URI_SSL_VERIFICATION = True

AVAILABLE_SCOPES = ['openid', 'phone']

JTI_TTL = 7 * 86400

DISCOVERY = {
    # 'issuer': f'{AGGREGATOR_HOST}',
    # 'token_endpoint': f'{AGGREGATOR_HOST}/oauth2/token',
    # 'jwks_uri': f'{AGGREGATOR_HOST}/jwks.json',
    'grant_types_supported': ['authorization_code', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
    'token_endpoint_auth_methods_supported': ['private_key_jwt'],
    'subject_types_supported': ['pairwise'],
    'response_types_supported': ['code'],
    'id_token_signing_alg_values_supported': ['RS256'],
    'request_object_signing_alg_values_supported': ['none', 'HS256', 'RS256'],
    'token_endpoint_auth_signing_alg_values_supported': ['RS256'],
    'claims_parameter_supported': False,
    'request_parameter_supported': False,
    'request_uri_parameter_supported': False,
    'claims_supported': ['aud', 'exp', 'nonce', 'acr', 'amr', 'auth_time', 'iat', 'iss', 'sub'],
    'ui_locales_supported': ['en'],
    'acr_values_supported': ['1', '2', '3'],
    'scopes_supported': ['openid', 'phone', 'device-location-verification-verify-read']
}

TELCO_FINDER_HOST = os.getenv('TELCO_FINDER_HOST', 'http://127.0.0.1:10010')
TELCO_FINDER_PATH = '/.well-known/webfinger'
API_SSL_VERIFICATION = False
API_HTTP_TIMEOUT = 10

try:
    sys.path.append('/etc/telcorouter/')
    from custom_settings import *
except ImportError as e:  # pragma: no cover
    pass
