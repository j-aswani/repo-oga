import logging
from collections import OrderedDict

import requests
from django.conf import settings

from aggregator.utils.http import HTTPClient
from aggregator.utils.utils import Singleton, get_cleaned_data

logger = logging.getLogger(settings.LOGGING_PREFIX)


class JWKSUriClient(object, metaclass=Singleton):

    def get_keys(self, jwks_uri):
        try:

            logger.info('JWKS URI request', extra={'data': OrderedDict([('method', 'GET'), ('url', jwks_uri)])})

            response = HTTPClient().get_session().get(jwks_uri, verify=settings.JWKS_URI_SSL_VERIFICATION)

            txt = str(response.content, 'utf-8')

            logger.info('JWKS URI response', extra={
                'data': OrderedDict([('method', 'GET'), ('url', jwks_uri), ('status', response.status_code), ('headers', get_cleaned_data(dict(response.headers))),
                                     ('response', txt), ('time', int(response.elapsed.total_seconds() * 1000))])})

            if response.status_code == requests.codes.ok:  # @UndefinedVariable
                return txt

            raise Exception(f'Invalid response: {response.status_code} - {response.text}')
        except Exception as e:
            logger.error('JWKS URI error', extra={'data': OrderedDict([('method', 'GET'), ('url', jwks_uri),
                                                                       ('exception', e.__class__.__name__), ('exception_msg', str(e.args[0]))])})
            return None
