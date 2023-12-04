import os

import sys

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = eval(os.getenv('DEBUG', "True").lower().title())

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'w(24-s_2m17w3iyxek^yecfvshn7$wwx2uf-03d-c079+j^x^v'

SILENCED_SYSTEM_CHECKS = ['urls.W002']

# Application definition

INSTALLED_APPS = [
    # 'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'authserver.oauth2',
    'authserver.wellknown',
    'authserver.health'
]

MIDDLEWARE = [
    'authserver.middleware.baikal.BaikalMiddleware',
    'authserver.middleware.log.LogMiddleware',
    'django.middleware.security.SecurityMiddleware',
    # 'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',
    # 'django.contrib.auth.middleware.AuthenticationMiddleware',
    # 'django.contrib.messages.middleware.MessageMiddleware',
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.locale.LocaleMiddleware',
]

ROOT_URLCONF = 'authserver.urls'

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
                'authserver.utils.context_processors.branding',
            ],
        },
    },
]

WSGI_APPLICATION = 'authserver.wsgi.application'

DATABASES = {}

MONGO_DATABASE_OPTIONS = {
    'default': {
        'host': f"mongodb://{os.getenv('DATABASE_HOST', 'localhost:27017')}/{os.getenv('DATABASE_NAME', 'baikal-authserver')}",
        'socketTimeoutMS': 30000
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'authserver',
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
SESSION_COOKIE_NAME = 'authserverid'
CSRF_COOKIE_NAME = 'authservercsrftoken'
CSRF_COOKIE_SECURE = True

AUTHENTICATION_BACKENDS = ('authserver.backends.authentication.AuthBackend',)

REST_FRAMEWORK = {
    'EXCEPTION_HANDLER': 'authserver.utils.exceptions.api_exception_handler'
}

CENSORER_MASKED_FIELDS = {"csrfmiddlewaretoken", "Cookie"}
CENSORER_FULL_MASKED_FIELDS = set([])
CENSORER_MASK = '----'
CENSORER_NUM_UNMASKED_CHARS = 4

LOGGING_ROOT = os.environ.get('LOGS_ROOT', os.path.join(os.path.dirname(__file__), 'logs'))
LOGGING_PREFIX = 'baikal-authserver'
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
        'baikal': {
            'format': '{"time":"%(UTCTimestamp)s","lvl":"%(levelname)s","corr":"%(correlator)s","trans":"%(transactionId)s","clientId":"%(clientId)s","user":"%(user)s","msg":"%(message)s","data":%(jsonMsg)s}'
        }
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        },
        'baikal_fields': {
            '()': 'authserver.utils.logger.LoggerFilter'
        }
    },
    'handlers': {
        'file': {  # define and name a handler
            'level': LOGGING_LEVEL,
            'filters': ['baikal_fields'],
            'class': 'logging.FileHandler',  # set the logging class to log to a file
            'formatter': 'baikal',  # define the formatter to associate
            'filename': os.path.join(LOGGING_ROOT, LOGGING_PREFIX + '.log')  # log file
        },
        'console': {
            'level': LOGGING_LEVEL,
            'filters': ['baikal_fields'],
            'class': 'logging.StreamHandler',
            'formatter': 'baikal',
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

COMPONENT = 'AUTHSERVER'

BRANDING = os.getenv('OPERATOR_ID', None)

AUTHSERVER_HOST = os.getenv('HOST', 'http://127.0.0.1:9010')
AUTHSERVER_ISSUER = AUTHSERVER_HOST
AUTHSERVER_AUDIENCES = [AUTHSERVER_ISSUER]
if os.getenv('ADDITIONAL_AUDIENCES') is not None:
    AUTHSERVER_AUDIENCES.extend(os.getenv('ADDITIONAL_AUDIENCES').split(','))
AUTHSERVER_KID = 'baikal-authserver'
AUTHSERVER_JWKS_URI = None

STATIC_URL = '/authserver/static/'
STATIC_VERSION = '1.0.0'

# ERROR_DESCRIPTION_FORMAT values: lowercase or phrase
ERROR_DESCRIPTION_FORMAT = 'phrase'

AUTHENTICATION_TTL = 600
AUTHORIZATION_CODE_TTL = 600
ACCESS_TOKEN_TTL = 600
ACCESS_TOKEN_TTL_BY_GRANT = {}
REFRESH_TOKEN_TTL = 1200
REFRESH_TOKEN_TTL_BY_GRANT = {}
AUTH_REQUEST_JWT_TTL = 600
AUTH_REQUEST_JWT_TIME_LEEWAY = 5

DEFAULT_ACR_VALUES = ['2']

BYPASS_INVALID_REQUEST_MESSAGES = ['acr_values', 'max_age', 'prompt', 'login_hint', 'display', 'ui_locales', 'id_token_hint']

JWT_SIGNING_ALGORITHM = 'RS256'
JWT_PRIVATE_KEY_FILE = os.path.join(os.path.dirname(__file__), 'tests/keys/jwtRS256_private.pem')
JWT_PRIVATE_KEY_PASSWORD = 'mobileconnect'
JWT_PUBLIC_KEY_FILE = os.path.join(os.path.dirname(__file__), 'tests/keys/jwtRS256_public.pem')
JWT_KID = 'defaultKid'
JWT_TTL = 300

OIDC_DISCOVERY_PATH = '/.well-known/openid-configuration'
OIDC_VERIFY_CERTIFICATE = True
OIDC_DATA_TTL = 15 * 60  # in seconds
OIDC_HTTP_TIMEOUT = 10  # in seconds

JWKS_URI_TTL = 900
JWKS_URI_SSL_VERIFICATION = True

AVAILABLE_SCOPES = ['openid', 'phone']

JTI_TTL = 7 * 86400

DISCOVERY = {
    # 'issuer': f'{AUTHSERVER_HOST}',
    # 'authorization_endpoint': f'{AUTHSERVER_HOST}/oauth2/authorize',
    # 'revocation_endpoint': f'{AUTHSERVER_HOST}/oauth2/revoke',
    # 'token_endpoint': f'{AUTHSERVER_HOST}/oauth2/token',
    # 'introspection_endpoint': f'{AUTHSERVER_HOST}/oauth2/introspect',
    # 'backchannel_authentication_endpoint': f'{AUTHSERVER_HOST}/oauth2/bc-authorize',
    # 'jwks_uri': f'{AUTHSERVER_HOST}/jwks.json',
    # 'userinfo_endpoint': f'{AUTHSERVER_HOST}/userinfo',
    'grant_types_supported': ['authorization_code', 'client_credentials', 'refresh_token', 'urn:ietf:params:oauth:grant-type:jwt-bearer'],
    'token_endpoint_auth_methods_supported': ['client_secret_post', 'client_secret_basic', 'private_key_jwt'],
    'revocation_endpoint_auth_methods_supported': ['client_secret_post', 'client_secret_basic', 'private_key_jwt'],
    'introspection_endpoint_auth_methods_supported': ['client_secret_post', 'client_secret_basic', 'private_key_jwt'],
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
    'scopes_supported': ['openid', 'phone'],
    'login_hint_token_supported': True,
    'backchannel_token_delivery_modes_supported': ['poll'],
    'backchannel_user_code_parameter_supported': False
}

CIBA_AUTHORIZATION_INTERVAL = 10
CIBA_AUTHORIZATION_TTL = 600

OPERATOR_ID = os.getenv('OPERATOR_ID', 'operator')
API_HOST = os.getenv('API_HOST', 'http://operator-platform-apigateway-1:8000')

try:
    sys.path.append('/etc/baikal-authserver/')
    from custom_settings import *
except ImportError as e:  # pragma: no cover
    pass
