import logging
import time
from collections import OrderedDict

import ujson as json
from django.conf import settings
from django.http.request import RawPostDataException
from django.utils.deprecation import MiddlewareMixin
from oauthlib.oauth2.rfc6749.errors import FatalClientError, OAuth2Error

from aggregator.utils.utils import get_cleaned_data

logger = logging.getLogger(settings.LOGGING_PREFIX)


def get_body_data(request):
    body = getattr(request, 'body', None)
    if body is not None:
        try:
            return json.loads(body)
        except:
            pass

        try:
            return body.decode('utf-8')
        except:
            return ''

    return ''


class LogMiddleware(MiddlewareMixin):

    """
    Log middleware. If it is enabled, each request/response will be logged.
    """

    ignore_paths = settings.LOGGING_IGNORE_PATHS

    show_response_views = settings.LOGGING_SHOW_RESPONSE_VIEW_NAMES

    def process_request(self, request):
        request.time = int(round(time.time() * 1000))
        try:
            data = OrderedDict()
            for field, value in [('method', lambda: request.method),
                                 ('path', lambda: request.path),
                                 ('params', lambda: dict(request.GET, **request.POST)),
                                 ('headers', lambda: dict(request.headers)),
                                 ('content', lambda: get_body_data(request))]:
                try:
                    data[field] = value()
                except RawPostDataException:
                    pass
                except Exception as e:
                    logger.error('Error processing request %s field: %s', field, str(e.args[0]))
            logger.info('Request', extra={'data': get_cleaned_data(data)})
        except Exception as e:
            logger.error('Error processing request: %s', str(e.args[0]))
        return None

    def process_view(self, request, view_func, view_args, view_kwargs):
        try:
            # logger.debug(view_func.view_class.__name__, extra={'data': get_cleaned_data(view_kwargs)})
            request.view = None
            if hasattr(view_func, 'view_class'):
                logger.debug(view_func.view_class.__name__, extra={'data': get_cleaned_data(view_kwargs)})
                request.view = view_func.view_class.__name__
        except Exception as e:
            logger.error('Error processing view: %s', str(e.args[0]))
        return None

    def process_exception(self, request, exception):
        try:
            if not isinstance(exception, FatalClientError) and not isinstance(exception, OAuth2Error):
                logger.error('Exception', exc_info=True, extra={'data': OrderedDict([('class', exception.__class__.__name__), ('message', str(exception.args[0]))])})
        except Exception as e:
            logger.error('Error processing exception: %s', str(e.args[0]))
        return None

    def process_response(self, request, response):
        try:
            log = self.__get_log(response)
            content = self.__get_content(request, response)

            data = {
                'status': response.status_code,
                'headers': dict(response.headers)
            }

            if hasattr(request, 'time'):
                data['time'] = int(round(time.time() * 1000)) - request.time

            if content is not None:
                data['content'] = content

            log('Response', extra={'data': get_cleaned_data(data)})
        except Exception as e:
            logger.error('Error processing response: %s', str(e.args[0]))
        return response

    def __get_log(self, response):
        log = logger.info
        if response.status_code / 100 == 5:
            log = logger.error
        elif response.status_code / 100 == 4:
            log = logger.warning
        return log

    def __get_content(self, request, response):
        content = None
        content_type = response.get('content-type', None)
        if content_type == 'application/json' and len(response.content) > 0 and \
                (response.status_code / 100 != 2 or request.view in self.show_response_views or settings.DEBUG):
            content = json.loads(response.content)
        return content
