from django.conf import settings
from django.conf.urls.static import static
from django.urls import re_path, include

from .oauth2.views import ApiView
from .utils.views import Handler404

urlpatterns = [
    re_path(r'^oauth2/', include('aggregator.oauth2.urls')),
    re_path(r'^\.well-known/', include('aggregator.wellknown.urls')),
    re_path(r'^api/', ApiView.as_view(), name='api'),
    re_path(r'^health/', include('aggregator.health.urls')),
]

# WARNING: not for production environment
urlpatterns.extend(static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0]))

if not settings.DEBUG:
    urlpatterns.append(re_path(r'^(?P<url>(.*))$', Handler404.as_view(), name='error404'))

