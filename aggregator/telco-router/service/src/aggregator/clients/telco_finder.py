import logging

import requests
from django.conf import settings
from jsonschema import FormatChecker
from jsonschema.validators import Draft7Validator

from aggregator.middleware.telcorouter import AggregatorMiddleware
from aggregator.utils.exceptions import log_exception, ServerErrorException
from aggregator.utils.http import do_request_call
from aggregator.utils.utils import Singleton

logger = logging.getLogger(settings.LOGGING_PREFIX)


WEBFINGER_PAYLOAD = {
    'type': 'object',
    'properties': {
        'subject': {
            'type': 'string'
        },
        'properties': {
            'type': 'object',
            'additionalProperties': {'type': 'string'}
        },
        'aliases': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        },
        'links': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'rel': {
                        'type': 'string'
                    },
                    'href': {
                        'type': 'string',
                        'format': 'uri'
                    },
                    'type': {
                        'type': 'string'
                    },
                    'titles': {
                        'type': 'object',
                        'additionalProperties': {'type': 'string'}
                    },
                    'properties': {
                        'type': 'object',
                        'additionalProperties': {'type': 'string'}
                    }
                },
                'required': ['rel', 'href']
            }
        }
    },
    'required': ['subject', 'properties', 'links'],
    'additionalProperties': False
}

WEBFINGER_VALIDATOR = Draft7Validator(WEBFINGER_PAYLOAD, format_checker=FormatChecker())


class TelcoFinderClient(object, metaclass=Singleton):

    WEBFINGER_FIELD_PROPERTIES = 'properties'
    WEBFINGER_FIELD_LINKS = 'links'
    WEBFINGER_FIELD_REL = 'rel'
    WEBFINGER_FIELD_HREF = 'href'
    WEBFINGER_PARAM_RESOURCE = 'resource'

    WEBFINGER_LINK_ISSUER = 'http://openid.net/specs/connect/1.0/issuer'
    WEBFINGER_LINK_APIS = 'apis'
    WEBFINGER_PROPERTY_OPERATOR_ID = 'operator_id'

    FIELD_ISSUER = 'iss'
    FIELD_APIS = 'apis'
    FIELD_OPERATOR_ID = 'operator_id'

    def get_routing_metadata(self, identity_type, identifier):
        api_name = 'Telco Finder'
        try:
            headers = {AggregatorMiddleware.AGGREGATOR_CORRELATOR_HEADER: AggregatorMiddleware.get_correlator(AggregatorMiddleware.get_current_request())}
            params = [
                (self.WEBFINGER_PARAM_RESOURCE, f'{identity_type}:{identifier}'),
                (self.WEBFINGER_FIELD_REL, self.WEBFINGER_LINK_ISSUER),
                (self.WEBFINGER_FIELD_REL, self.WEBFINGER_LINK_APIS)
            ]
            response = do_request_call(api_name, 'GET', settings.TELCO_FINDER_HOST + settings.TELCO_FINDER_PATH, params=params,
                                       headers=headers, verify=settings.API_SSL_VERIFICATION, timeout=settings.API_HTTP_TIMEOUT)
            if response.status_code == requests.codes.ok:  # @UndefinedVariable
                payload = response.json()
                WEBFINGER_VALIDATOR.validate(payload)
                return self._prepare_routing_metadata(payload)
            elif response.status_code == requests.codes.not_found:  # @UndefinedVariable
                return None
        except Exception as e:
            log_exception(e)
        raise ServerErrorException(f'{api_name} is unavailable')

    def _prepare_routing_metadata(self, telco_finder_response):
        return {
            self.FIELD_OPERATOR_ID: self._get_property(telco_finder_response, self.WEBFINGER_PROPERTY_OPERATOR_ID),
            self.FIELD_ISSUER: self._get_link(telco_finder_response, self.WEBFINGER_LINK_ISSUER),
            self.FIELD_APIS: self._get_link(telco_finder_response, self.WEBFINGER_LINK_APIS)
        }

    def _get_link(self, telco_finder_response, link):
        try:
            return next(x for x in telco_finder_response[self.WEBFINGER_FIELD_LINKS] if x[self.WEBFINGER_FIELD_REL] == link)[self.WEBFINGER_FIELD_HREF]
        except StopIteration:
            raise ServerErrorException(f'Link {link} is unavailable in webfinger response')

    def _get_property(self, telco_finder_response, prop):
        if prop in telco_finder_response[self.WEBFINGER_FIELD_PROPERTIES]:
            return telco_finder_response[self.WEBFINGER_FIELD_PROPERTIES][prop]
        raise ServerErrorException(f'Property {prop} is unavailable in webfinger response')
