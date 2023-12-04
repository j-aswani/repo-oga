from authserver.oauth2.models import ApplicationCollection


class AuthUser(object):

    id = None
    is_active = True
    data = None

    def __init__(self, data):
        self.id = data["_id"]
        self.data = data

    def save(self):
        pass

    def delete(self):
        pass

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True


class AuthBackend(object):

    def authenticate(self, request, username=None, password=None):
        user = self.get_user(username)
        if user is not None:
            if user.data[ApplicationCollection.FIELD_CONSUMER_SECRET] == password:
                return user
        return None

    def get_user(self, username):
        user = ApplicationCollection.find_one_by_id(username, True)
        if user is not None:
            user = AuthUser(user)
        return user