# Aggregator

This is an Authorization Server that implements the following functionalities of OAuth 2.0 and OpenID Connect protocols:

* [OIDC Authorization Code Flow](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
* [JWT Bearer Grant](https://datatracker.ietf.org/doc/html/rfc7523)
* [Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636) 
* [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

## Getting Started

### Development

Aggregator is a Python application, based on [Django](https://www.djangoproject.com/) and [oauthlib](https://github.com/oauthlib/oauthlib) libraries, that uses a [Mongo](https://www.mongodb.com/) database to store data.

First of all, you need to create a Python (>=3.10) [virtual environment](https://docs.python.org/3/library/venv.html) and activate it.

Then you have to install the component package dependencies in your activated virtual environment:

```sh
$ pip install -r ./service/src/requirements.txt
```

To run a lightweight development web server on the local machine:

```sh
$ cd ./service/src
$ python manage.py runserver 0.0.0.0:10010 --noreload --settings=aggregator.settings
```

You can check your server installation by accessing to the Aggregator´s OpenID Connect Discovery metadata:

```sh
$ curl http://127.0.0.1:10010/oauth2/.well-known/openid-configuration
```

#### Testing

To run the component tests:

```sh
$ cd ./service/src
$ python manage.py test --settings=aggregator.devtest_settings
```

## Database

### Collections

* apps

```json
{
  "_id" : "73902489-c201-4819-bdf9-3708a484fe21",
  "consumer_secret" : "3184428a-1ea4-4e1c-9969-b623f36fbc2f",
  "name" : "Demo App",
  "description" : "App for testing",
  "developer" : {
    "email" : "johndoe@demoapp.com",
    "name" : "John Doe"
  },
  "status" : "active",
  "grants" : [
    {
      "grant_type" : "urn:ietf:params:oauth:grant-type:jwt-bearer",
      "scopes" : [
        "device-location-verification-verify-read"
      ]
    }
  ],
  "sector_identifier_uri" : "http://localhost:3000",
  "jwks_uri" : "http://demo-app:3000/api/jwks"
}
```

## FLows

### JWT Bearer Grant

#### Assertion Content

```json
{
  "iss": "73902489-c201-4819-bdf9-3708a484fe21", 
  "aud": "http://127.0.0.1:10010/oauth2/authorize", 
  "jti": "70d9ee54-70b7-415e-a410-05f018cbc080", 
  "iat": 1682666155, 
  "exp": 1682666455, 
  "sub": "tel:+34618051526",
  "scope": "device-location-verification-verify-read"
}
```

