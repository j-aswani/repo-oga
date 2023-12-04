import logging

import requests
from cachetools import TTLCache
from cachetools import cachedmethod
from django.conf import settings

from aggregator.middleware.telcorouter import AggregatorMiddleware
from aggregator.utils.exceptions import log_exception, ServerErrorException
from aggregator.utils.http import do_request_call
from aggregator.utils.utils import Singleton

logger = logging.getLogger(settings.LOGGING_PREFIX)


class OidcClient(object, metaclass=Singleton):

    def __init__(self):
        self.cache = TTLCache(maxsize=1024, ttl=settings.OIDC_DATA_TTL)

    @cachedmethod(lambda self: self.cache)
    def get_metadata(self, issuer):
        api_name = 'OIDC Discovery'
        try:
            headers = {AggregatorMiddleware.AGGREGATOR_CORRELATOR_HEADER: AggregatorMiddleware.get_correlator(AggregatorMiddleware.get_current_request())}
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
