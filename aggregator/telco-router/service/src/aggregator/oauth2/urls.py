from django.urls import re_path

from aggregator.oauth2.views import MetadataView, TokenView, JWKSetView, AuthorizeView, AuthorizeCallbackView

urlpatterns = [
    re_path(r'^\.well-known/openid-configuration/?$', MetadataView.as_view(), name='aggregator-metadata'),
    re_path(r'^authorize/?$', AuthorizeView.as_view(), name='aggregator-authorize'),
    re_path(r'^authorize/callback/?$', AuthorizeCallbackView.as_view(), name='aggregator-callback'),
    re_path(r'^token/?$', TokenView.as_view(), name='aggregator-token'),
    re_path(r'^jwks/?$', JWKSetView.as_view(), name='jwkset')
]
