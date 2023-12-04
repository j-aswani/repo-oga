from django.urls import path

from authserver.health.views import CheckView

urlpatterns = [
    path(r'check', CheckView.as_view(), name='health-check'),
]
