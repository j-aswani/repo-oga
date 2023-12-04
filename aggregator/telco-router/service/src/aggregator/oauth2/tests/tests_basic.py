import json
import time
from base64 import b64encode, urlsafe_b64encode
from datetime import datetime, timedelta
from uuid import uuid4

from django.conf import settings
from django.core.cache import cache
from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS
from jwcrypto.jwt import JWT

from aggregator.oauth2.models import ApplicationCollection, JtiCollection
from aggregator.utils.jwk import JWKManager, JWKSUriClient
from aggregator.utils.tests.base import AggregatorTestCase

USER_PHONE_IDENTITY = '+34618051526'

USER_PCR = {
    '_id': '2128c01f-dcc8-4fde-a74e-eba2f9b1a3af',
    'user': f'tel:{USER_PHONE_IDENTITY}',
    'sector_identifier': 'www.foo.bar'
}

APPLICATION = {
    '_id': '68399c5b-3cfa-4348-9f96-33d379077d71',
    'consumer_secret': '4e10a18f-5ebd-42ec-8444-2641eb3d5633',
    'name': ['Foo', 'Foo2'],
    'status': 'active',
    'redirect_uri': 'https:///www.foo.bar/callback',
    'sector_identifier_uri': 'https://www.foo.bar/uris',
    "jwks_uri": "https://www.foo.bar/jwks.json",
    'grants': [
        {
            'grant_type': 'authorization_code',
            'scopes': [
                'openid',
                'phone',
                'atp'
            ]
        },
        {
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'scopes': [
                'openid',
                'phone',
                'atp'
            ]
        }
    ],
    'created': datetime.utcnow() - timedelta(seconds=10000),
    'updated': datetime.utcnow()
}

DEFAULT_CORRELATOR = 'corr1234'

with open(settings.SP_JWT_PRIVATE_KEY_FILE, 'rb') as f:
    content = f.read()
    SP_JWT_PRIVATE_KEY = JWK.from_pem(content, settings.SP_JWT_PRIVATE_KEY_PASSWORD.encode('utf-8') if settings.SP_JWT_PRIVATE_KEY_PASSWORD is not None else None)

with open(settings.SP_JWT_PUBLIC_KEY_FILE, 'rb') as f:
    content = f.read()
    SP_JWT_PUBLIC_KEY = JWK.from_pem(content)
    public_key_json = json.loads(SP_JWT_PUBLIC_KEY.export(False))
    public_key_json['kid'] = settings.SP_JWT_KID
    SP_JWKS_URI = {'keys': []}
    SP_JWKS_URI['keys'].append(public_key_json)

with open(settings.OPERATOR_JWT_PRIVATE_KEY_FILE, 'rb') as f:
    content = f.read()
    OPERATOR_JWT_PRIVATE_KEY = JWK.from_pem(content, settings.OPERATOR_JWT_PRIVATE_KEY_PASSWORD.encode('utf-8') if settings.OPERATOR_JWT_PRIVATE_KEY_PASSWORD is not None else None)

with open(settings.OPERATOR_JWT_PUBLIC_KEY_FILE, 'rb') as f:
    content = f.read()
    OPERATOR_JWT_PUBLIC_KEY = JWK.from_pem(content)
    public_key_json = json.loads(OPERATOR_JWT_PUBLIC_KEY.export(False))
    public_key_json['kid'] = settings.OPERATOR_JWT_KID
    OPERATOR_JWKS_URI = {'keys': []}
    OPERATOR_JWKS_URI['keys'].append(public_key_json)


def get_signed_jwt(obj, alg, kid, key):
    header = {'alg': alg}
    if kid:
        header['kid'] = kid

    jwt = JWT(header=header, claims=obj)
    jwt.make_signed_token(key)
    return jwt.serialize(True)


def get_unsigned_jwt(claims):
    # Workaround: Library does not support unsigned JWTs
    key = urlsafe_b64encode(APPLICATION['consumer_secret'].encode()).decode('utf-8').rstrip('=')
    jwkey = JWK(k=key, kty='oct')

    jwstoken = JWS(json.dumps(claims))
    jwstoken.allowed_algs.append('none')
    jwstoken.add_signature(jwkey, None, {'alg': 'none'})
    return jwstoken.serialize(compact=True)


class BasicTestCase(AggregatorTestCase):

    @classmethod
    def __empty_dbs(cls):
        ApplicationCollection.objects.delete_many({})
        JtiCollection.objects.delete_many({})

    def setUp(self):
        super().setUp()

        # Clear Chache
        cache.clear()

        self.__empty_dbs()

        # Dropping Singletons
        JWKManager._drop()
        JWKSUriClient._drop()

    def tearDown(self):
        self.__empty_dbs()

    def assertErrorPage(self, response, status, error, description, desc_start=False):
        self.assertEqual(response.status_code, status)
        content = str(response.content, 'utf-8')
        self.assertInHTML('<h3>%s</h3>' % error, content)
        if desc_start:
            self.assertContains(response, '<p>%s' % description, status_code=status)
        else:
            self.assertInHTML('<p>%s</p>' % description, content)

    def assertJsonError(self, response, status, error, description=None):
        self.assertEqual(response.status_code, status)
        body = response.json()
        self.assertEqual(body['error'], error)
        if description is None:
            self.assertNotIn('error_description', body)
        else:
            self.assertEqual(body['error_description'], description)

    @classmethod
    def get_authorization_header(cls, username, password):
        basic_key = b64encode(f'{username}:{password}'.encode('utf-8')).decode('utf-8')
        return f'Basic {basic_key}'

    @classmethod
    def get_default_headers(cls, **kwargs):
        return {
            'HTTP_AUTHORIZATION': cls.get_authorization_header(APPLICATION[ApplicationCollection.FIELD_ID], APPLICATION[ApplicationCollection.FIELD_CONSUMER_SECRET])
        }

    @classmethod
    def get_default_client_assertion(cls, client_id=None):
        now = time.time()
        return {
            'iss': client_id or APPLICATION['_id'],
            'sub': client_id or APPLICATION['_id'],
            'aud': settings.AGGREGATOR_HOST,
            'jti': str(uuid4()),
            'iat': int(now),
            'exp': int(now) + 300
        }

    @classmethod
    def do_mocking(cls, m, jwks_uri_params=None):
        if jwks_uri_params is None:
            m.get(APPLICATION['jwks_uri'], text=json.dumps(SP_JWKS_URI))
        else:
            m.get(APPLICATION['jwks_uri'], **jwks_uri_params)

        m.get('http://oauth.operator.com/jwks', text=json.dumps(OPERATOR_JWKS_URI))

        m.get("http://api.aggregator.com/.well-known/webfinger",
              json={
                  "subject": "type:value",
                  "properties": {
                      "operator_id": "TELEFONICA"
                  },
                  "links": [
                      {
                          "rel": "http://openid.net/specs/connect/1.0/issuer",
                          "href": "http://oauth.operator.com"
                      },
                      {
                          "rel": "apis",
                          "href": "http://api.operator.com"
                      }
                  ]
              })

        m.get("http://oauth.operator.com/.well-known/openid-configuration",
              json={
                  "issuer": "http://oauth.operator.com",
                  "token_endpoint": "http://oauth.operator.com/token",
                  "authorization_endpoint": "http://oauth.operator.com/authorize",
                  "jwks_uri": "http://oauth.operator.com/jwks",
              })
