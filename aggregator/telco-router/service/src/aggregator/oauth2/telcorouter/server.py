import logging

from django.conf import settings
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.openid.connect.core.grant_types import AuthorizationTokenGrantDispatcher
from oauthlib.openid.connect.core.tokens import JWTToken

from aggregator.oauth2.telcorouter.endpoints import AggregatorTokenEndpoint, AggregatorApiEndpoint, AggregatorAuthorizationEndpoint
from aggregator.oauth2.telcorouter.grant_types import AggregatorJWTBearerGrant, GRANT_TYPE_JWT_BEARER, AggregatorOAuth2AuthorizationCodeGrant, AggregatorOIDCAuthorizationCodeGrant, \
    RESPONSE_TYPE_CODE, GRANT_TYPE_AUTHORIZATION_CODE
from aggregator.oauth2.telcorouter.tokens import access_token_expires_in

logger = logging.getLogger(settings.LOGGING_PREFIX)


class AggregatorServer(AggregatorAuthorizationEndpoint, AggregatorTokenEndpoint, AggregatorApiEndpoint):

    def __init__(self, request_validator, token_expires_in=None, token_generator=None, refresh_token_generator=None, *args, **kwargs):

        self.bearer = BearerToken(request_validator, token_generator, access_token_expires_in, refresh_token_generator)
        self.jwt = JWTToken(request_validator, token_generator, token_expires_in, refresh_token_generator)

        self.auth_grant = AggregatorOAuth2AuthorizationCodeGrant(request_validator)
        self.openid_connect_auth = AggregatorOIDCAuthorizationCodeGrant(request_validator)

        self.token_grant_choice = AuthorizationTokenGrantDispatcher(request_validator, default_grant=self.auth_grant, oidc_grant=self.openid_connect_auth)
        self.jwt_bearer_grant = AggregatorJWTBearerGrant(request_validator)

        AggregatorAuthorizationEndpoint.__init__(self, default_response_type=RESPONSE_TYPE_CODE,
                                         response_types={
                                             RESPONSE_TYPE_CODE: self.openid_connect_auth
                                         },
                                         default_token_type=self.bearer)

        AggregatorTokenEndpoint.__init__(self, default_grant_type=None,
                                     grant_types={
                                         GRANT_TYPE_AUTHORIZATION_CODE: self.token_grant_choice,
                                         GRANT_TYPE_JWT_BEARER: self.jwt_bearer_grant,
                                     },
                                     default_token_type=self.bearer)

        AggregatorApiEndpoint.__init__(self, request_validator)