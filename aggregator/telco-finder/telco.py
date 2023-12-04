import logging

import requests
from retry import retry

from exceptions import InvalidAccessTokenException
from oidc import OidcClient
from settings import OIDC_VERIFY_CERTIFICATE, OIDC_HTTP_TIMEOUT, OPERATOR_CLIENT_ID, OPERATOR_TELCOFINDER_SCOPES, OIDC_WEBFINGER_PATH
from utils import do_request_call, Singleton

logger = logging.getLogger()


class OperatorClient(object, metaclass=Singleton):

    @retry(exceptions=InvalidAccessTokenException, tries=2, delay=0, logger=logger)
    def webfinger(self, telco, params):
        resource = 'AuthServer Webfinger'
        token = OidcClient().get_cc_access_token(telco['iss'], OPERATOR_CLIENT_ID, OPERATOR_TELCOFINDER_SCOPES)
        try:
            headers = {
                'Authorization': f'Bearer {token["access_token"]}',
                'Content-Type': 'application/json'
            }
            response = do_request_call(resource, 'GET', telco['apis'] + OIDC_WEBFINGER_PATH,
                                       headers=headers, params=params,
                                       verify=OIDC_VERIFY_CERTIFICATE, timeout=OIDC_HTTP_TIMEOUT)
            if response.status_code == requests.codes.ok:  # @UndefinedVariable
                return response.json()
            elif response.status_code == requests.codes.not_found:  # @UndefinedVariable
                return None
            elif response.status_code == requests.codes.unauthorized:  # @UndefinedVariable
                OidcClient().remove_cached_access_token(token["access_token"])
                raise InvalidAccessTokenException(f'{resource} is unavailable (Invalid access token)')
        except InvalidAccessTokenException:
            raise
        except Exception as e:
            logger.error(f'Exception in {resource}: {e.args[0]}')
        raise Exception(f'{resource} is unavailable')
