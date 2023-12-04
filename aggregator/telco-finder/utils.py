import importlib
import logging

from jwcrypto.jwk import JWK
from requests import Session

from exceptions import ServerErrorException
from settings import JWT_PRIVATE_KEY_PASSWORD, JWT_PRIVATE_KEY_FILE

logger = logging.getLogger()


class Singleton(type):

    def __init__(self, name, bases, dct):
        self.__instance = None
        type.__init__(self, name, bases, dct)

    def __call__(self, *args, **kw):
        if self.__instance is None:
            self.__instance = type.__call__(self, *args, **kw)
        return self.__instance

    def _drop(self):
        # Drop the instance (for testing purposes).
        del self._Singleton__instance
        self.__instance = None


class HTTPClient(object, metaclass=Singleton):

    session = Session()

    def get_session(self):
        return self.session


def do_request_call(api_name, method, url, *args, **kwargs):

    logger.info(f'{api_name} request {method} {url}')

    response = HTTPClient().get_session().request(method, url, *args, **kwargs)

    if response.status_code // 100 == 2:
        log = logger.info
    elif response.status_code // 100 == 5:
        log = logger.error
    else:
        log = logger.warning

    log(f'{api_name} response {method} {url} - {response.status_code} in {int(response.elapsed.total_seconds() * 1000)}ms')
    return response


class JWKManager(object, metaclass=Singleton):

    jwt_private_key = None

    def __init__(self):

        try:
            with open(JWT_PRIVATE_KEY_FILE, "rb") as f:
                content = f.read()
                self.jwt_private_key = JWK.from_pem(content, JWT_PRIVATE_KEY_PASSWORD.encode('utf-8') if JWT_PRIVATE_KEY_PASSWORD is not None else None)
        except Exception as e:
            logger.error('Error processing JWT private key (%s): %s', JWT_PRIVATE_KEY_FILE, str(e.args[0]))

    def get_private_key(self):
        if self.jwt_private_key is not None:
            return self.jwt_private_key
        raise ServerErrorException('JWT private key is not properly configured')


def load_class(path, params=None):
    module_name, class_name = path.rsplit(".", 1)
    _class = getattr(importlib.import_module(module_name), class_name)
    if params is None:
        return _class()
    else:
        return _class(**params)
