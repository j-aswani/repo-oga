from django.apps import AppConfig

from authserver.oauth2.models import AuthenticationCollection, CodeCollection, \
    TokenCollection, JtiCollection, UserPcrCollection


class AuthenticationConfig(AppConfig):

    name = "authserver.oauth2"

    def ready(self):
        AuthenticationCollection.ensure_all_indexes()
        CodeCollection.ensure_all_indexes()
        TokenCollection.ensure_all_indexes()
        JtiCollection.ensure_all_indexes()
        UserPcrCollection.ensure_all_indexes()
