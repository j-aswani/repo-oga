import logging

from django.conf import settings
from oauthlib.oauth2.rfc6749.grant_types import ClientCredentialsGrant
from oauthlib.oauth2.rfc6749.grant_types.refresh_token import RefreshTokenGrant
from oauthlib.oauth2.rfc6749.tokens import BearerToken
from oauthlib.openid.connect.core.grant_types.dispatchers import AuthorizationTokenGrantDispatcher
from oauthlib.openid.connect.core.tokens import JWTToken

from authserver.oauth2.baikal.endpoints import BaikalAuthorizationEndpoint, \
    BaikalRevocationEndpoint, BaikalIntrospectEndpoint, BaikalTokenEndpoint, BaikalUserInfoEndpoint, BaikalCibaAuthorizationEndpoint
from authserver.oauth2.baikal.grant_types import BaikalOAuth2AuthorizationCodeGrant, \
    BaikalOIDCAuthorizationCodeGrant, GRANT_TYPE_REFRESH_TOKEN, \
    GRANT_TYPE_CLIENT_CREDENTIALS, GRANT_TYPE_AUTHORIZATION_CODE, \
    RESPONSE_TYPE_CODE, BaikalJWTBearerGrant, GRANT_TYPE_JWT_BEARER, GRANT_TYPE_CIBA, BaikalCibaGrant
from authserver.oauth2.baikal.tokens import access_token_expires_in

logger = logging.getLogger(settings.LOGGING_PREFIX)


class BaikalServer(BaikalAuthorizationEndpoint, BaikalCibaAuthorizationEndpoint,
                   BaikalTokenEndpoint, BaikalRevocationEndpoint, BaikalIntrospectEndpoint,
                   BaikalUserInfoEndpoint):

    def __init__(self, request_validator, token_expires_in=None, token_generator=None, refresh_token_generator=None, *args, **kwargs):

        self.bearer = BearerToken(request_validator, token_generator, access_token_expires_in, refresh_token_generator)
        self.jwt = JWTToken(request_validator, token_generator, token_expires_in, refresh_token_generator)

        self.auth_grant = BaikalOAuth2AuthorizationCodeGrant(request_validator)
        self.openid_connect_auth = BaikalOIDCAuthorizationCodeGrant(request_validator)

        BaikalAuthorizationEndpoint.__init__(self, default_response_type=RESPONSE_TYPE_CODE,
                                             response_types={
                                                 RESPONSE_TYPE_CODE: self.openid_connect_auth
                                             },
                                             default_token_type=self.bearer)

        self.token_grant_choice = AuthorizationTokenGrantDispatcher(request_validator, default_grant=self.auth_grant, oidc_grant=self.openid_connect_auth)
        self.ciba_grant = BaikalCibaGrant(request_validator)
        self.jwt_bearer_grant = BaikalJWTBearerGrant(request_validator)
        self.credentials_grant = ClientCredentialsGrant(request_validator)
        self.refresh_grant = RefreshTokenGrant(request_validator)

        BaikalCibaAuthorizationEndpoint.__init__(self, self.ciba_grant, ciba_default_token_type=self.bearer)

        BaikalTokenEndpoint.__init__(self, default_grant_type=GRANT_TYPE_AUTHORIZATION_CODE,
                                     grant_types={
                                         GRANT_TYPE_AUTHORIZATION_CODE: self.token_grant_choice,
                                         GRANT_TYPE_CLIENT_CREDENTIALS: self.credentials_grant,
                                         GRANT_TYPE_REFRESH_TOKEN: self.refresh_grant,
                                         GRANT_TYPE_JWT_BEARER: self.jwt_bearer_grant,
                                         GRANT_TYPE_CIBA: self.ciba_grant
                                     },
                                     default_token_type=self.bearer)

        BaikalRevocationEndpoint.__init__(self, request_validator, supported_token_types=['access_token', 'refresh_token]'])
        BaikalIntrospectEndpoint.__init__(self, request_validator)

        BaikalUserInfoEndpoint.__init__(self, request_validator)
