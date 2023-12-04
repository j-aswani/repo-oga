import logging
import time
from collections import OrderedDict, namedtuple

import ujson as json
from django.conf import settings
from jsonschema.exceptions import ValidationError
from jwcrypto.jwe import InvalidJWEData
from jwcrypto.jws import InvalidJWSSignature
from jwcrypto.jwt import JWT

from aggregator.utils.exceptions import JWTException, InvalidParameterValueError
from aggregator.utils.jwk import JWKManager
from aggregator.utils.schemas import FIELD_ISSUER, FIELD_AUDIENCE, FIELD_ISSUED_TIME, FIELD_EXPIRATION, FIELD_NOT_BEFORE
from aggregator.utils.utils import get_cleaned_data

logger = logging.getLogger(settings.LOGGING_PREFIX)


FIELD_KID = 'kid'
FIELD_ALGORITHM = 'alg'
FIELD_ENCRYPTION = 'enc'
FIELD_CORRELATOR = 'corr'

JWTObject = namedtuple('JWT', ['header', 'payload'])


def validate_jws_header(jwstoken, algs, kid):
    if algs is not None and (FIELD_ALGORITHM not in jwstoken.jose_header or jwstoken.jose_header[FIELD_ALGORITHM] not in algs):
        raise JWTException('Invalid alg value')
    if kid and FIELD_KID not in jwstoken.jose_header:
        raise JWTException('Invalid kid value')


def get_jws_info(jwstoken, key, issuer, audiences=None, validator=None):
    try:
        if key:
            jwstoken.verify(key)

        payload = json.loads(jwstoken.payload)

        logger.debug('JWT payload', extra={'data': OrderedDict([('header', jwstoken.jose_header), ('payload', get_cleaned_data(payload))])})

        if validator is not None:
            validator.validate(payload)

        if FIELD_ISSUER in payload and issuer is not None and payload[FIELD_ISSUER] != issuer:
            raise JWTException('Invalid issuer')
        if FIELD_AUDIENCE in payload and audiences is not None and \
                (len(set(audiences) & set(payload[FIELD_AUDIENCE])) == 0 if isinstance(payload[FIELD_AUDIENCE], list) else payload[FIELD_AUDIENCE] not in audiences):
            raise JWTException('Invalid audience')

        now = int(time.time())
        if FIELD_ISSUED_TIME in payload and payload[FIELD_ISSUED_TIME] - settings.AUTH_REQUEST_JWT_TIME_LEEWAY > now:
            raise JWTException('JWT comes from future')

        if FIELD_EXPIRATION in payload and payload[FIELD_EXPIRATION] + settings.AUTH_REQUEST_JWT_TIME_LEEWAY < now:
            raise JWTException('Expired JWT')

        if FIELD_NOT_BEFORE in payload and payload[FIELD_NOT_BEFORE] - settings.AUTH_REQUEST_JWT_TIME_LEEWAY > now:
            raise JWTException('JWT is not valid yet')

        return JWTObject(jwstoken.jose_header, payload)
    except JWTException as e:
        raise
    except InvalidJWEData as e:
        raise JWTException('Invalid JWT content')
    except ValidationError as e:
        raise InvalidParameterValueError(str(".".join(e.path)), e.message)
    except InvalidJWSSignature as e:
        raise
    except Exception as e:
        raise JWTException(str(e.args[0]))


def build_jws(payload):
    try:
        jwt = JWT(header={'alg': settings.JWT_SIGNING_ALGORITHM, 'kid': settings.JWT_KID}, claims=payload)
        jwt.make_signed_token(JWKManager().get_private_key())
        return jwt.serialize(True)
    except Exception as e:
        raise JWTException(str(e.args[0]))
