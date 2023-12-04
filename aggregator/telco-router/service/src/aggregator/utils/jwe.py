import logging
import time
from collections import namedtuple, OrderedDict

import ujson as json
from django.conf import settings
from jwcrypto import jwk, jwe
from jwcrypto.common import json_encode
from jwcrypto.jwe import InvalidJWEData
from jwcrypto.jwk import JWK

from aggregator.utils.schemas import FIELD_AUDIENCE, \
    FIELD_ISSUED_TIME, FIELD_EXPIRATION
from aggregator.utils.utils import get_cleaned_data
from .exceptions import JWTException
from .utils import Singleton

logger = logging.getLogger(settings.LOGGING_PREFIX)

FIELD_KID = 'kid'
FIELD_ALGORITHM = 'alg'
FIELD_ENCRYPTION = 'enc'
FIELD_CORRELATOR = 'corr'

JWTObject = namedtuple('JWT', ['header', 'payload'])


class KeySetStorage(object, metaclass=Singleton):

    def __init__(self):
        self.kset = jwk.JWKSet()
        for key in settings.SECRET_KEYS:
            self.kset.add(JWK(**key))

    def get_key(self, kid):
        return self.kset.get_key(kid)


def get_jwe_token(jwt_doc):
    try:
        if len(jwt_doc) == 0:
            raise JWTException('Empty JWT')

        jwetoken = jwe.JWE()
        jwetoken.deserialize(jwt_doc)

        return jwetoken
    except JWTException as e:
        raise
    except InvalidJWEData as e:
        raise JWTException('Invalid JWT content')
    except Exception as e:
        raise JWTException(str(e.args[0]))


def get_jwe_info(jwe_token, audience=None, validator=None):
    try:
        jwe_token.decrypt(KeySetStorage().get_key(jwe_token.jose_header[FIELD_KID]))

        payload = json.loads(jwe_token.payload)
        logger.debug('JWT payload', extra={'data': OrderedDict([('header', jwe_token.jose_header), ('payload', get_cleaned_data(payload))])})

        if validator is not None:
            validator.validate(payload)

        if FIELD_AUDIENCE in payload and audience is not None and audience != payload[FIELD_AUDIENCE]:
            raise JWTException('Invalid audience')

        now = int(time.time())
        if FIELD_ISSUED_TIME in payload and payload[FIELD_ISSUED_TIME] - settings.AUTH_REQUEST_JWT_TIME_LEEWAY > now:
            raise JWTException('JWT comes from future')

        if FIELD_EXPIRATION in payload and payload[FIELD_EXPIRATION] + settings.AUTH_REQUEST_JWT_TIME_LEEWAY < now:
            raise JWTException('Expired JWT token')

        return JWTObject(jwe_token.jose_header, payload)
    except JWTException as e:
        raise
    except InvalidJWEData as e:
        raise JWTException(str(e.args[0]))
    except Exception as e:
        raise JWTException(str(e.args[0]))


def build_jwe(payload, correlator, kid):
    try:
        key = KeySetStorage().get_key(kid)
        if key is None:
            raise Exception(f'Key is not available ({kid})')

        jwe_token = jwe.JWE(json.dumps(payload, escape_forward_slashes=False),
                            json_encode({
                               FIELD_ALGORITHM: 'A256KW',
                               FIELD_ENCRYPTION: "A256CBC-HS512",
                               FIELD_KID: kid,
                               FIELD_CORRELATOR: correlator
                            }))

        jwe_token.add_recipient(key)
        return jwe_token.serialize(compact=True)
    except Exception as e:
        raise JWTException(str(e.args[0]))
