from django.conf import settings
from django.conf.urls.static import static
from django.urls import re_path, include

from .utils.views import Handler404

urlpatterns = [
    re_path(r'^oauth2/', include('authserver.oauth2.urls')),
    re_path(r'^\.well-known/', include('authserver.wellknown.urls')),
    re_path(r'^health/', include('authserver.health.urls')),
]

# WARNING: not for production environment
urlpatterns.extend(static(settings.STATIC_URL, document_root=settings.STATICFILES_DIRS[0]))

if not settings.DEBUG:
    urlpatterns.append(re_path(r'^(?P<url>(.*))$', Handler404.as_view(), name='error404'))

