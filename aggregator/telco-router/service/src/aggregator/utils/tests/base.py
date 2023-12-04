import json
from collections import namedtuple

from django.test import TestCase

MockedRequest = namedtuple('MockedRequest', ['url', 'method', 'headers', 'params', 'body'])


class AggregatorTestCase(TestCase):

    databases = set()

    def __init__(self, methodName='runTest'):
        super().__init__(methodName)
        self.maxDiff = None

    def __call__(self, *args, **kwds):
        print(str(self))
        return super().__call__(*args, **kwds)

    @classmethod
    def get_request_from_history(cls, m, index=-1):
        request = m.request_history[index]

        return MockedRequest(request._request.url, request._request.method, request._request.headers, request.qs, json.loads(request.text) if request.text else None)
