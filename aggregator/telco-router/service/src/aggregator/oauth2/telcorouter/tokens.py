import time

from django.conf import settings
from oauthlib.oauth2.rfc6749.tokens import random_token_generator

from aggregator.middleware.telcorouter import AggregatorMiddleware
from aggregator.utils.jwe import build_jwe
from aggregator.utils.schemas import FIELD_JTI, FIELD_ISSUER, FIELD_AUDIENCE, FIELD_SCOPES, FIELD_CLIENT_ID, FIELD_EXPIRATION, FIELD_ISSUED_TIME


def access_token_expires_in(request):
    return request.token['expires_in']


def jwt_token_generator(request):
    now = int(time.time())

    access_token = {
        FIELD_JTI: random_token_generator(request),
        FIELD_ISSUER: settings.AGGREGATOR_ISSUER,
        FIELD_AUDIENCE: settings.AGGREGATOR_ISSUER,
        FIELD_CLIENT_ID: request.client_id,
        FIELD_SCOPES: request.scopes,
        FIELD_ISSUED_TIME: now,
        FIELD_EXPIRATION: now + request.token["expires_in"],
        'access_token': request.token["access_token"],
        'routing': request.routing
    }
    return build_jwe(access_token, AggregatorMiddleware.get_correlator(request), settings.JWE_ACCESS_TOKEN_KID)
