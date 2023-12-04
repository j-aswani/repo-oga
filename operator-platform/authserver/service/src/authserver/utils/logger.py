# -*- coding: utf-8 -*-

'''

Common LogRecord attributes: http://docs.python.org/2/library/logging.html#logrecord-attributes
Added LogRecord attributes

Attribute name        Format                      Description

remoteIp              %(remoteIp)s                Remote client IP
remoteHost            %(remoteHost)s              Remote HOST
requestMethod         %(requestMethod)s           Request Method
contentType           %(contentType)s             Request Content-Type
contentLength         %(contentLength)s           Request Content-Lenght
queryString           %(queryString)s             Request Query Params
httpAuthentication    %(httpAuthentication)s      Request Authentication header
serverName            %(serverName)               Host Name
serverPort            %(serverPort)s              Host Port
correlator            %(correlator)s              UNICA correlator
transactionId         %(transactionId)s           TransactionID from identifying request
component             %(component)s               Component name from Django App Name
UTCTimestamp          %(UTCTimestamp)s            Timestamp
requestPath           %(requestPath)s             Request PATH
operation             %(operation)s               Operation description (requestMethod + requestPath)
clientId              %(clientId)s                Application Identifier
user                  %(user)s                    User identity
jsonMsg               %(jsonMsg)s                 Message in JSON format

'''

import logging
from datetime import datetime
from logging import Filter

import ujson as json
from django.conf import settings

from authserver.middleware.baikal import BaikalMiddleware

logger = logging.getLogger(settings.LOGGING_PREFIX)


class LoggerFilter(Filter, object):

    UNKNOWN_VALUE = 'NA'

    def filter(self, record):

        record.UTCTimestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        record.remoteIp = '0.0.0.0'
        record.remoteHost = self.UNKNOWN_VALUE
        record.requestMethod = self.UNKNOWN_VALUE
        record.contentType = self.UNKNOWN_VALUE
        record.contentLength = '0'
        record.queryString = ''
        record.httpAuthentication = ''
        record.serverName = self.UNKNOWN_VALUE
        record.serverPort = self.UNKNOWN_VALUE
        record.transactionId = self.UNKNOWN_VALUE
        record.correlator = self.UNKNOWN_VALUE
        record.component = self.UNKNOWN_VALUE
        record.requestPath = self.UNKNOWN_VALUE
        record.operation = self.UNKNOWN_VALUE
        record.clientId = self.UNKNOWN_VALUE
        record.user = self.UNKNOWN_VALUE
        record.jsonMsg = '{}'

        try:

            record.component = settings.COMPONENT
            request = BaikalMiddleware.get_current_request()

            if hasattr(record, 'data'):
                record.jsonMsg = json.dumps(record.data, sort_keys=False, escape_forward_slashes=False)

            if request is not None:
                record.remoteIp = request.META.get('REMOTE_ADDR', '0.0.0.0')
                record.remoteHost = request.META.get('REMOTE_HOST', self.UNKNOWN_VALUE)
                record.serverName = request.META.get('SERVER_NAME', self.UNKNOWN_VALUE)
                record.serverPort = request.META.get('SERVER_PORT', self.UNKNOWN_VALUE)
                record.requestMethod = request.META.get('REQUEST_METHOD', self.UNKNOWN_VALUE)
                record.contentType = request.META.get('CONTENT_TYPE', self.UNKNOWN_VALUE)
                record.contentLength = request.META.get('CONTENT_LENGTH', '0')
                record.queryString = request.META.get('QUERY_STRING', '')
                record.httpAuthentication = request.headers.get('Authorization', '')

                record.transactionId = BaikalMiddleware.get_transaction(request) or self.UNKNOWN_VALUE
                record.correlator = BaikalMiddleware.get_correlator(request) or self.UNKNOWN_VALUE
                record.requestPath = request.get_full_path()

                record.clientId = BaikalMiddleware.get_client_id(request) or self.UNKNOWN_VALUE
                record.user = BaikalMiddleware.get_user(request) or self.UNKNOWN_VALUE

        except Exception as e:
            pass

        return True
