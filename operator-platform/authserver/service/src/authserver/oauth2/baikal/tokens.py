import time

from django.conf import settings
from jwcrypto.jwt import JWT
from oauthlib.oauth2.rfc6749.tokens import random_token_generator

from authserver.oauth2.models import Grant, CodeCollection
from authserver.utils.jwk import JWKManager
from authserver.utils.schemas import FIELD_JTI, FIELD_ISSUER, FIELD_AUDIENCE, FIELD_SCOPES, FIELD_CLIENT_ID, FIELD_EXPIRATION, FIELD_ISSUED_TIME


def access_token_expires_in(request):
    grant = getattr(request, 'grant', {})
    return grant.get(Grant.FIELD_ACCESS_TOKEN_TTL, settings.ACCESS_TOKEN_TTL_BY_GRANT.get(request.grant_type, settings.ACCESS_TOKEN_TTL))


def refresh_token_expires_in(request):
    grant = getattr(request, 'grant', {})
    return grant.get(Grant.FIELD_REFRESH_TOKEN_TTL, settings.REFRESH_TOKEN_TTL_BY_GRANT.get(request.grant_type, settings.REFRESH_TOKEN_TTL))


def jwt_token_generator(request):

    access_token = {
        FIELD_JTI: random_token_generator(request),
        FIELD_ISSUER: settings.AUTHSERVER_ISSUER,
        FIELD_AUDIENCE: [request.client_id],
        FIELD_SCOPES: request.scopes,
        FIELD_CLIENT_ID: request.client_id,
        FIELD_ISSUED_TIME: int(time.time()),
        FIELD_EXPIRATION: int(time.time()) + request.expires_in
    }

    if hasattr(request, 'auth'):
        for claim in [CodeCollection.FIELD_SUB, CodeCollection.FIELD_UID, CodeCollection.FIELD_ACR, CodeCollection.FIELD_AMR, CodeCollection.FIELD_AUTH_TIME]:
            access_token[claim] = request.auth.get(claim, None)

    jwt = JWT(header={'alg': settings.JWT_SIGNING_ALGORITHM, 'kid': JWKManager().get_public_kid()}, claims=access_token)
    jwt.make_signed_token(JWKManager().get_private_key())
    return jwt.serialize(True)
