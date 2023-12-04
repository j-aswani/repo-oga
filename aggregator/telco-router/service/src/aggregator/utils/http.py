import logging
import re
from base64 import b64decode
from collections import OrderedDict

import ujson as json
from django.conf import settings
from django.shortcuts import render
from requests.sessions import Session

from aggregator.utils.utils import Singleton, get_cleaned_data, censor_form_urlencoded_str, censor_obj_str

logger = logging.getLogger(settings.LOGGING_PREFIX)


class HTTPClient(object, metaclass=Singleton):

    session = Session()

    def get_session(self):
        return self.session

def _get_cleaned_body(obj, data):
    if obj:
        return json.dumps(get_cleaned_data(obj))
    try:
        return censor_form_urlencoded_str(data)
    except:
        pass
    return data


def do_request_call(api_name, method, url, *args, **kwargs):

    cleaned_body = _get_cleaned_body(kwargs.get('json', None), kwargs.get('data').decode("utf-8") if ('data' in kwargs and isinstance(kwargs.get('data'), bytes)) else kwargs.get('data', None))

    logger.info(f'{api_name} request', extra={'data': OrderedDict([('method', method), ('url', url),
                                                                   ('headers', get_cleaned_data(kwargs.get('headers', None))),
                                                                   ('params', get_cleaned_data(kwargs.get('params', None))), ('body', cleaned_body)])})
    response = HTTPClient().get_session().request(method, url, *args, **kwargs)

    if response.status_code // 100 == 2:
        log = logger.info
    elif response.status_code // 100 == 5:
        log = logger.error
    else:
        log = logger.warning

    try:
        content = censor_obj_str(response.text)
    except Exception:
        content = response.text

    log(f'{api_name} response', extra={'data': OrderedDict([('method', method), ('url', url), ('status', response.status_code), ('headers', dict(response.headers)),
                                                            ('body', content), ('time', int(response.elapsed.total_seconds() * 1000))])})
    return response


def render_response(request, template, *args, **kwargs):
    logger.debug('Rendering template', extra={'data': OrderedDict([('template', template)])})
    return render(request, template, *args, **kwargs)


BASIC_AUTH_PATTERN = re.compile(r'Basic (.*)', re.IGNORECASE)
BEARER_AUTH_PATTERN = re.compile(r'Bearer (.*)', re.IGNORECASE)


def extract_credentials_from_basic_auth(text):
    try:
        m = BASIC_AUTH_PATTERN.match(text)
        if m is not None:
            chars = m.group(1)
            chars += '=' * (-len(chars) % 4)
            credentials = b64decode(chars).decode().split(':', 1)
            return credentials
        message = "Missing 'Basic' prefix"
    except Exception as e:
        message = e.args[0]
    raise Exception('Invalid Basic Auth format: %s' % message)


def extract_credentials_from_bearer_auth(text):
    try:
        m = BEARER_AUTH_PATTERN.match(text)
        if m is not None:
            return m.group(1)
        message = "Missing 'Bearer' prefix"
    except Exception as e:
        message = e.args[0]
    raise Exception('Invalid Bearer Auth format: %s' % message)
