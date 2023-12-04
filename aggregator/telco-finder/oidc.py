import logging
import uuid
from threading import Lock
from urllib.parse import urlencode

import requests
import time
from cachetools import TTLCache
from cachetools import cachedmethod
from jwcrypto.jwt import JWT

from exceptions import ServerErrorException
from settings import OIDC_DATA_TTL, OIDC_VERIFY_CERTIFICATE, OIDC_HTTP_TIMEOUT, OIDC_DISCOVERY_PATH, JWT_SIGNING_ALGORITHM, JWT_KID
from utils import Singleton, JWKManager, do_request_call

logger = logging.getLogger()


class OidcClient(object, metaclass=Singleton):

    cc_access_tokens_lock = Lock()
    cc_access_tokens = {}

    def __init__(self):
        self.cache = TTLCache(maxsize=1024, ttl=OIDC_DATA_TTL)

    @cachedmethod(lambda self: self.cache)
    def get_metadata(self, issuer):
        api_name = 'OIDC Discovery'
        try:
            response = do_request_call(api_name, 'GET', issuer + OIDC_DISCOVERY_PATH,
                                       headers={}, verify=OIDC_VERIFY_CERTIFICATE, timeout=OIDC_HTTP_TIMEOUT)
            if response.status_code == requests.codes.ok:  # @UndefinedVariable
                return response.json()
            logger.error(f'Invalid {api_name} response: {response.status_code}')
        except Exception as e:
            logger.error(f'Exception in {api_name}: {e.args[0]}')
        raise ServerErrorException(f'{api_name} is unavailable')

    def get_data(self, issuer, data):
        metadata = self.get_metadata(issuer)
        return metadata.get(data, None)

    @staticmethod
    def get_client_authentication_assertion(issuer, client_id):
        claims = {
            'iss': client_id,
            'sub': client_id,
            'aud': issuer,
            'jti': str(uuid.uuid4()),
            'iat': int(time.time()),
            'exp': int(time.time()) + 60,
            'nbf': int(time.time()) - 60,
        }
        jwt = JWT(header={'alg': JWT_SIGNING_ALGORITHM, 'kid': JWT_KID}, claims=claims)
        jwt.make_signed_token(JWKManager().get_private_key())
        return jwt.serialize(True)

    def get_cc_access_token(self, issuer, client_id, scopes):
        api_name = 'AuthServer CC Token'
        with self.cc_access_tokens_lock:
            key = self._get_cc_token_key(issuer, scopes)
            access_token = self.cc_access_tokens.get(key, None)
            if access_token is None or access_token['expires_at'] < int(time.time()):
                try:
                    token_uri = self.get_data(issuer, 'token_endpoint')
                    if token_uri is not None:
                        headers = {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        }

                        data = urlencode({
                            'grant_type': 'client_credentials',
                            'scope': ' '.join(scopes),
                            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                            'client_assertion': self.get_client_authentication_assertion(issuer, client_id)
                        })
                        response = do_request_call(api_name, 'POST', token_uri, headers=headers, data=data,
                                                   verify=OIDC_VERIFY_CERTIFICATE, timeout=OIDC_HTTP_TIMEOUT)
                        if response.status_code == requests.codes.ok:  # @UndefinedVariable
                            token = response.json()
                            token['expires_at'] = int(time.time()) + token['expires_in'] - 5
                            self.cc_access_tokens[key] = token
                            return token
                except Exception as e:
                    logger.error(f'Exception in {api_name}: {e.args[0]}')
                raise Exception(f'{api_name} is unavailable')

            return access_token

    def remove_cached_access_token(self, access_token):
        for k, v in list(self.cc_access_tokens.items()):
            if v['access_token'] == access_token:
                del self.cc_access_tokens[k]
                break

    @staticmethod
    def _get_cc_token_key(issuer, scopes):
        return '-'.join([issuer, '_'.join(scopes or [])])