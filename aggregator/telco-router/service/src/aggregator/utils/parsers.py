import codecs
import json
import logging

from django.conf import settings
from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser
from rest_framework.utils import json

logger = logging.getLogger(settings.LOGGING_PREFIX)


def object_pairs_hook(pairs):
    keys = {}
    for k, v in pairs:
        if k in keys:
            raise ParseError(f"JSON parse error - '{k}' key is already present in JSON object")
        keys[k] = v
    return keys


class AggregatorJSONParser(JSONParser):

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Parses the incoming bytestream as JSON and returns the resulting data.
        """
        parser_context = parser_context or {}
        encoding = parser_context.get('encoding', settings.DEFAULT_CHARSET)

        try:
            decoded_stream = codecs.getreader(encoding)(stream)
            parse_constant = json.strict_constant if self.strict else None
            return json.load(decoded_stream, parse_constant=parse_constant,
                             object_pairs_hook=object_pairs_hook)
        except ValueError as exc:
            raise ParseError('JSON parse error - %s' % str(exc))
