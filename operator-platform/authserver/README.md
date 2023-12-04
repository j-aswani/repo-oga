# Authserver

This is an Authorization Server that implements the following functionalities of OAuth 2.0 and OpenID Connect protocols:

* [OIDC Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
* [OpenID Connect Client-Initiated Backchannel Authentication Flow (CIBA)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)
* [JWT Bearer Grant](https://datatracker.ietf.org/doc/html/rfc7523)
* [OAuth 2.0 Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)
* [OAuth 2.0 Refresh Token](https://www.rfc-editor.org/rfc/rfc6749#section-1.5)
* [OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
* [OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
* [OIDC Userinfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)
* [Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636) 
* [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

## Getting Started

### Development

Authserver is a Python application, based on [Django](https://www.djangoproject.com/) and [oauthlib](https://github.com/oauthlib/oauthlib) libraries, that uses a [Mongo](https://www.mongodb.com/) database to store data.

First of all, you need to create a Python (>=3.10) [virtual environment](https://docs.python.org/3/library/venv.html) and activate it.

Then you have to install the component package dependencies in your activated virtual environment:

```sh
$ pip install -r ./service/src/requirements.txt
```

To run a lightweight development web server on the local machine:

```sh
$ cd ./service/src
$ python manage.py runserver 0.0.0.0:9012 --noreload --settings=authserver.settings
```

You can check your server installation by accessing to the Authserver´s OpenID Connect Discovery metadata:

```sh
$ curl http://127.0.0.1:9010/oauth2/authorize/.well-known/openid-configuration
```

#### Testing

To run the component tests:

```sh
$ cd ./service/src
$ python manage.py test --settings=authserver.devtest_settings
```

## Database

### Collections

* apps

```json
{ 
    "_id": "73902489-c201-4819-bdf9-3708a484fe21", 
    "consumer_secret": "3184428a-1ea4-4e1c-9969-b623f36fbc2f", 
    "name" : "Demo App", 
    "description": "App for testing", 
    "redirect_uri": [ 
        "http://localhost:3000/api/auth/callback/telco", 
        "http://192.168.1.161:3001/api/auth/callback/telco", 
        "http://127.0.0.1:3000/api/auth/callback/telco" ,
        "http://localhost:3000/login/camara/callback" 
    ], 
    "developer": { 
        "email": "johndoe@demoapp.com",
        "name": "John Doe" 
    }, 
    "status": "active",
    "grants": [ 
        { 
            "grant_type": "authorization_code", 
            "scopes": [ 
                "openid",
                "device-location-verification-verify-read" 
            ] 
        }, 
        { 
            "grant_type": "urn:openid:params:grant-type:ciba", 
            "scopes": [
                "openid",
                "device-location-verification-verify-read" 
            ] 
        }, 
        { 
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", 
            "scopes": [ 
                "device-location-verification-verify-read" 
            ] 
        },
        { 
            "grant_type": "client_credentials",
            "scopes": [ 
                "discovery:read" 
            ] 
        } 
    ], 
    "sector_identifier_uri": "http://localhost:3000", 
    "jwks_uri": "http://demo-app2:3000/api/jwks" 
}
```

* user_pcrs 
```json
{
  "_id": "b767dabc-007d-4ac2-b1b3-c1e104fa3b50",
  "sector_identifier": "www.demoapp.com",
  "user": "tel:+34618051526"
}
```

## FLows

### JWT Bearer Grant

#### Assertion Content

```json
{
  "iss": "73902489-c201-4819-bdf9-3708a484fe21", 
  "aud": "http://127.0.0.1:9010/oauth2/authorize", 
  "jti": "70d9ee54-70b7-415e-a410-05f018cbc080", 
  "iat": 1682666155, 
  "exp": 1682666455, 
  "sub": "tel:+34618051526",
  "scope": "device-location-verification-verify-read"
}
```

