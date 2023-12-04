from django.apps import AppConfig

from aggregator.oauth2.models import JtiCollection


class AuthenticationConfig(AppConfig):

    name = "aggregator.oauth2"

    def ready(self):
        JtiCollection.ensure_all_indexes()
