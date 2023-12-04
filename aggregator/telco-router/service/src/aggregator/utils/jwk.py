import logging

import ujson as json
from cachetools import TTLCache
from cachetools import cachedmethod
from django.conf import settings
from jwcrypto.jwk import JWK, JWKSet

from aggregator.clients.jwks import JWKSUriClient
from aggregator.utils.exceptions import ServerErrorException, \
    UnavailableSignatureError
from aggregator.utils.utils import Singleton

logger = logging.getLogger(settings.LOGGING_PREFIX)


class JWKManager(object, metaclass=Singleton):

    jwt_private_key = None
    jwt_public_key = None

    def __init__(self):

        self.cache = TTLCache(maxsize=1024, ttl=settings.JWKS_URI_TTL)

        try:
            with open(settings.JWT_PRIVATE_KEY_FILE, "rb") as f:
                content = f.read()
                self.jwt_private_key = JWK.from_pem(content, settings.JWT_PRIVATE_KEY_PASSWORD.encode('utf-8') if settings.JWT_PRIVATE_KEY_PASSWORD is not None else None)
        except Exception as e:
            logger.error('Error processing JWT private key (%s): %s', settings.JWT_PRIVATE_KEY_FILE, str(e.args[0]))

        try:
            with open(settings.JWT_PUBLIC_KEY_FILE, "rb") as f:
                content = f.read()
                self.jwt_public_key = JWK.from_pem(content)
        except Exception as e:
            logger.error('Error processing JWT public key (%s): %s', settings.JWT_PUBLIC_KEY_FILE, str(e.args[0]))

    def get_private_key(self):
        if self.jwt_private_key is not None:
            return self.jwt_private_key
        raise ServerErrorException('JWT private key is not properly configured')

    def get_public_key(self):
        if self.get_public_key is not None:
            return self.jwt_public_key
        raise ServerErrorException('JWT public key is not properly configured')

    def export_public(self):
        obj = json.loads(self.jwt_public_key.export())
        if settings.JWT_KID is not None:
            obj['kid'] = settings.JWT_KID
        return obj

    def get_public_kid(self):
        return settings.JWT_KID or self.jwt_public_key.key_id

    @cachedmethod(lambda self: self.cache)
    def get_app_public_key(self, jwks_uri, kid):
        logger.debug("Getting keys form jwks_uri: %s", jwks_uri)
        keyset = JWKSUriClient().get_keys(jwks_uri)
        if keyset is None:
            raise UnavailableSignatureError()
        jwks_set = JWKSet.from_json(keyset)
        key = jwks_set.get_key(kid)
        if key is None:
            raise UnavailableSignatureError()
        return key
