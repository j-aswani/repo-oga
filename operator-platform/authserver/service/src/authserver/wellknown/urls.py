from django.urls import re_path

from authserver.oauth2.views import MetadataView
from authserver.wellknown.views import WebFingerView

urlpatterns = [
    re_path(r'^openid-configuration/?$', MetadataView.as_view(), name='openid-configuration'),
    re_path(r'^webfinger/?$', WebFingerView.as_view(), name='webfinger')
]
