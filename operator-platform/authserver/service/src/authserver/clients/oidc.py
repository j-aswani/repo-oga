import logging

import requests
from cachetools import TTLCache
from cachetools import cachedmethod
from django.conf import settings

from authserver.middleware.baikal import BaikalMiddleware
from authserver.utils.exceptions import log_exception, ServerErrorException
from authserver.utils.http import do_request_call
from authserver.utils.utils import Singleton

logger = logging.getLogger(settings.LOGGING_PREFIX)


class OidcClient(object, metaclass=Singleton):

    def __init__(self):
        self.cache = TTLCache(maxsize=1024, ttl=settings.OIDC_DATA_TTL)

    @cachedmethod(lambda self: self.cache)
    def get_metadata(self, issuer):
        api_name = 'OIDC Discovery'
        try:
            headers = {BaikalMiddleware.BAIKAL_CORRELATOR_HEADER: BaikalMiddleware.get_correlator(BaikalMiddleware.get_current_request())}
            response = do_request_call(api_name, 'GET', issuer + settings.OIDC_DISCOVERY_PATH,
                                       headers=headers, verify=settings.OIDC_VERIFY_CERTIFICATE, timeout=settings.OIDC_HTTP_TIMEOUT)
            if response.status_code == requests.codes.ok:  # @UndefinedVariable
                return response.json()
        except Exception as e:
            log_exception(e)
        raise ServerErrorException(f'{api_name} is unavailable')

    def get_data(self, issuer, data):
        metadata = self.get_metadata(issuer)
        return metadata.get(data, None)


