from django.urls import re_path

from aggregator.oauth2.views import MetadataView

urlpatterns = [
    re_path(r'^openid-configuration/?$', MetadataView.as_view(), name='openid-configuration'),
]
