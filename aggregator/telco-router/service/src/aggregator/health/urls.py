from django.urls import path

from aggregator.health.views import CheckView

urlpatterns = [
    path(r'check', CheckView.as_view(), name='health-check'),
]
