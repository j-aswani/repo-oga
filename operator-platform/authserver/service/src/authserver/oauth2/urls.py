from django.urls import re_path

from authserver.oauth2.views import AuthorizeView, TokenView, RevokeView, IntrospectView, JWKSetView, UserInfoView, CibaAuthorizeView

urlpatterns = [
    re_path(r'^authorize/?$', AuthorizeView.as_view(), name='authserver-authorize'),
    re_path(r'^bc-authorize/?$', CibaAuthorizeView.as_view(), name='authserver-bc-authorize'),
    re_path(r'^token/?$', TokenView.as_view(), name='authserver-token'),
    re_path(r'^revoke/?$', RevokeView.as_view(), name='authserver-revoke'),
    re_path(r'^introspect/?$', IntrospectView.as_view(), name='authserver-introspect'),
    re_path(r'^jwks/?$', JWKSetView.as_view(), name='jwkset'),
    re_path(r'^userinfo/?$', UserInfoView.as_view(), name='userinfo')
]
