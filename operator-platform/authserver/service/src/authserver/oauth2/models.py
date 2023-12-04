import calendar
import logging
from datetime import datetime
from urllib.parse import urlparse
from uuid import uuid4

import pymongo
from django.conf import settings
from django.core.cache import cache
from pymongo.collection import ReturnDocument

from authserver.utils.database import BaikalCollection

logger = logging.getLogger(settings.LOGGING_PREFIX)


class AuthenticationCollection(BaikalCollection):

    collection_name = 'authentications'

    INDEX_EXPIRATION = 'expiration'
    INDEX_IDP_STATE = 'idp_state'

    FIELD_ID = '_id'
    FIELD_CREATION = 'creation'
    FIELD_PROMPT = 'prompt'
    FIELD_CLIENT_ID = 'client_id'
    FIELD_CLIENT_NAME = 'client_name'
    FIELD_REDIRECT_URI = 'redirect_uri'
    FIELD_RESPONSE_TYPE = 'response_type'
    FIELD_STATE = 'state'
    FIELD_DISPLAY = 'display'
    FIELD_NONCE = 'nonce'
    FIELD_UI_LOCALES = 'ui_locales'
    FIELD_LOGIN_HINT = 'login_hint'
    FIELD_CLAIMS = 'claims'
    FIELD_ACR_VALUES = 'acr_values'
    FIELD_MAX_AGE = 'max_age'
    FIELD_SCOPES = 'scopes'

    @classmethod
    def ensure_all_indexes(cls):
        try:
            logger.info('Creating authentication indexes...')
            super().ensure_indexes([
                {'name': cls.INDEX_EXPIRATION, 'keys': [(cls.FIELD_CREATION, pymongo.ASCENDING)], 'expireAfterSeconds': settings.AUTHENTICATION_TTL}
            ])
            logger.info('Authentication indexes created')
        except Exception as e:
            logger.error('Unable to create authentication indexes: %s', str(e.args[0]))

    @classmethod
    def find_one(cls, authentication_id):
        auth = cls.objects.find_one({cls.FIELD_ID: authentication_id})
        if auth is not None and \
                calendar.timegm(datetime.timetuple(datetime.utcnow())) - calendar.timegm(datetime.timetuple(auth[cls.FIELD_CREATION])) > settings.AUTHENTICATION_TTL:
            return None
        return auth

    @classmethod
    def update(cls, authentication):
        if cls.FIELD_CREATION not in authentication:
            authentication[cls.FIELD_CREATION] = datetime.utcnow()
        return cls.objects.update_one({cls.FIELD_ID: authentication[cls.FIELD_ID]},
                                      {'$set': authentication}, upsert=True)


class CodeCollection(BaikalCollection):

    collection_name = 'codes'

    INDEX_EXPIRATION = 'expiration'

    FIELD_ID = '_id'
    FIELD_CREATION = 'creation'
    FIELD_CLIENT_ID = 'client_id'
    FIELD_CLIENT_NAME = 'client_name'
    FIELD_REDIRECT_URI = 'redirect_uri'
    FIELD_GRANT = 'grant'
    FIELD_NONCE = 'nonce'
    FIELD_LOGIN_HINT = 'login_hint'
    FIELD_SUB = 'sub'
    FIELD_UID = 'uid'
    FIELD_AUTH_TIME = 'auth_time'
    FIELD_ACR = 'acr'
    FIELD_AMR = 'amr'
    FIELD_SCOPES = 'scopes'
    FIELD_CLAIMS = 'claims'
    FIELD_CODE_CHALLENGE = 'code_challenge'
    FIELD_CODE_CHALLENGE_METHOD = 'code_challenge_method'
    FIELD_CORRELATOR = 'corr'

    @classmethod
    def ensure_all_indexes(cls):
        try:
            logger.info('Creating code indexes...')
            super().ensure_indexes([
                {'name': cls.INDEX_EXPIRATION, 'keys': [(cls.FIELD_CREATION, pymongo.ASCENDING)], 'expireAfterSeconds': settings.AUTHORIZATION_CODE_TTL}
            ])
            logger.info('Code indexes created')
        except Exception as e:
            logger.error('Unable to create code indexes: %s', str(e.args[0]))

    @classmethod
    def find_one(cls, code):
        auth = cls.objects.find_one({cls.FIELD_ID: code})
        if auth is not None and \
                calendar.timegm(datetime.timetuple(datetime.utcnow())) - calendar.timegm(datetime.timetuple(auth[cls.FIELD_CREATION])) > settings.AUTHORIZATION_CODE_TTL:
            return None
        return auth

    @classmethod
    def update(cls, data):
        if cls.FIELD_CREATION not in data:
            data[cls.FIELD_CREATION] = datetime.utcnow()
        return cls.objects.insert_one(data)

    @classmethod
    def remove(cls, code):
        return cls.objects.delete_one({cls.FIELD_ID: code})


class TokenCollection(BaikalCollection):

    collection_name = 'tokens'

    INDEX_EXPIRATION = 'expiration'
    INDEX_ACCESS_TOKEN = 'access_token'
    INDEX_REFRESH_TOKEN = 'refresh_token'
    INDEX_UID = 'uid'

    FIELD_ID = '_id'
    FIELD_ACCESS_TOKEN = 'access_token'
    FIELD_REFRESH_TOKEN = 'refresh_token'
    FIELD_ID_TOKEN = 'id_token'
    FIELD_CLIENT_ID = 'client_id'
    FIELD_CLIENT_NAME = 'client_name'
    FIELD_GRANT_TYPE = 'grant_type'
    FIELD_SCOPES = 'scopes'
    FIELD_CLAIMS = 'claims'
    FIELD_SUB = 'sub'
    FIELD_UID = 'uid'
    FIELD_TYPE = 'type'
    FIELD_CONSENT_DATE = 'consent_date'
    FIELD_ACCESS_TOKEN_TTL = 'access_token_ttl'
    FIELD_ACCESS_TOKEN_EXPIRATION = 'expires_at'
    FIELD_REFRESH_TOKEN_TTL = 'refresh_token_ttl'
    FIELD_REFRESH_TOKEN_EXPIRATION = 'refresh_token_expires_at'
    FIELD_CREATION = 'creation'
    FIELD_EXPIRATION = 'expiration'

    @classmethod
    def ensure_all_indexes(cls):
        try:
            logger.info('Creating token indexes...')
            super().ensure_indexes([
                {'name': cls.INDEX_ACCESS_TOKEN, 'keys': [(cls.FIELD_ACCESS_TOKEN, pymongo.ASCENDING)], 'unique': True},
                {'name': cls.INDEX_REFRESH_TOKEN, 'keys': [(cls.FIELD_REFRESH_TOKEN, pymongo.ASCENDING)], 'unique': True, 'sparse': True},
                {'name': cls.INDEX_UID, 'keys': [(cls.FIELD_UID, pymongo.ASCENDING)]},
                {'name': cls.INDEX_EXPIRATION, 'keys': [(cls.FIELD_EXPIRATION, pymongo.ASCENDING)], 'expireAfterSeconds': 0}
            ])
            logger.info('Token indexes created')
        except Exception as e:
            logger.error('Unable to create token indexes: %s', str(e.args[0]))

    @classmethod
    def find_one(cls, access_token=None, refresh_token=None, client_id=None):
        q = {}
        if access_token is not None:
            q[cls.FIELD_ACCESS_TOKEN] = access_token
        if refresh_token is not None:
            q[cls.FIELD_REFRESH_TOKEN] = refresh_token
        if client_id is not None:
            q[cls.FIELD_CLIENT_ID] = client_id
        token = cls.objects.find_one(q)
        if token is not None:
            now = calendar.timegm(datetime.timetuple(datetime.utcnow()))
            if (access_token is not None and now > calendar.timegm(datetime.timetuple(token[cls.FIELD_ACCESS_TOKEN_EXPIRATION]))) \
                    or (refresh_token is not None and now > calendar.timegm(datetime.timetuple(token[cls.FIELD_REFRESH_TOKEN_EXPIRATION]))):
                return None
        return token

    @classmethod
    def save(cls, data):
        return cls.objects.insert_one(data)

    @classmethod
    def update(cls, token_id, data):
        return cls.objects.update_one({cls.FIELD_ID: token_id}, {'$set': data})

    @classmethod
    def remove_access_token(cls, access_token):
        cls.objects.delete_one({cls.FIELD_ACCESS_TOKEN: access_token})

    @classmethod
    def remove_any(cls, token, client_id=None):
        q = {'$or': [{cls.FIELD_ACCESS_TOKEN: token}, {cls.FIELD_REFRESH_TOKEN: token}]}
        if client_id is not None:
            q[cls.FIELD_CLIENT_ID] = client_id
        return cls.objects.find_one_and_delete(q)


class CibaAuthorizationCollection(BaikalCollection):

    collection_name = 'ciba_authorizations'

    INDEX_EXPIRATION = 'expiration'

    FIELD_ID = '_id'
    FIELD_CORRELATOR = 'corr'
    FIELD_CLIENT_ID = 'client_id'
    FIELD_STATUS = 'status'
    FIELD_CREATION = 'creation'
    FIELD_SCOPES = 'scopes'
    FIELD_LOGIN_HINT = 'login_hint'
    FIELD_ACR_VALUES = 'acr_values'
    FIELD_UID = 'uid'
    FIELD_ACR = 'acr'
    FIELD_AMR = 'amr'
    FIELD_AUTH_TIME = 'auth_time'
    FIELD_GRANT = 'grant'
    FIELD_ERROR = 'error'
    FIELD_ERROR_DESCRIPTION = 'error_description'

    STATUS_PENDING = 'PENDING'
    STATUS_ERROR = 'ERROR'
    STATUS_OK = 'OK'

    @classmethod
    def ensure_all_indexes(cls):
        try:
            logger.info('Creating CIBA authorization indexes...')
            super().ensure_indexes([
                {'name': cls.INDEX_EXPIRATION, 'keys': [(cls.FIELD_CREATION, pymongo.ASCENDING)], 'expireAfterSeconds': settings.CIBA_AUTHORIZATION_TTL}
            ])
            logger.info('CIBA authorization indexes created')
        except Exception as e:
            logger.error('Unable to create CIBA authorization indexes: %s', str(e.args[0]))

    @classmethod
    def find_one(cls, client_id, auth_id=None, ):
        q = {cls.FIELD_CLIENT_ID: client_id}
        if auth_id:
            q[cls.FIELD_ID] = auth_id
        auth = cls.objects.find_one(q)
        if auth is not None and \
                calendar.timegm(datetime.timetuple(datetime.utcnow())) - calendar.timegm(datetime.timetuple(auth[cls.FIELD_CREATION])) > settings.CIBA_AUTHORIZATION_TTL:
            return None
        return auth

    @classmethod
    def update(cls, authorization):
        if cls.FIELD_CREATION not in authorization:
            authorization[cls.FIELD_CREATION] = datetime.utcnow()
        return cls.objects.update_one({cls.FIELD_ID: authorization[cls.FIELD_ID]}, {'$set': authorization}, upsert=True)

    @classmethod
    def remove(cls, auth_id):
        cls.objects.delete_one({cls.FIELD_ID: auth_id})


class JtiCollection(BaikalCollection):

    collection_name = 'jtis'

    INDEX_EXPIRATION = 'expiration'
    INDEX_JTI = 'jti'

    FIELD_CLIENT_ID = 'client_id'
    FIELD_JTI = 'jti'
    FIELD_EXPIRATION = 'exp'

    @classmethod
    def ensure_all_indexes(cls):
        try:
            logger.info('Creating JTIs indexes...')
            super().ensure_indexes([
                {'name': cls.INDEX_EXPIRATION, 'keys': [(cls.FIELD_EXPIRATION, pymongo.ASCENDING)], 'expireAfterSeconds': 0},
                {'name': cls.INDEX_JTI, 'keys': [(cls.FIELD_CLIENT_ID, pymongo.ASCENDING), (cls.FIELD_JTI, pymongo.ASCENDING)], 'unique': True}
            ])
            logger.info('JTIs indexes created')
        except Exception as e:
            logger.error('Unable to create JTIs indexes: %s', str(e.args[0]))

    @classmethod
    def insert_jti(cls, client_id, jti, expiration):
        return cls.objects.insert_one({cls.FIELD_CLIENT_ID: client_id, cls.FIELD_JTI: jti, cls.FIELD_EXPIRATION: expiration})


class ApplicationCollection(BaikalCollection):

    collection_name = 'apps'

    FIELD_ID = '_id'
    FIELD_NAME = 'name'
    FIELD_REDIRECT_URI = 'redirect_uri'
    FIELD_SECTOR_IDENTIFIER_URI = 'sector_identifier_uri'
    FIELD_JWKS_URI = 'jwks_uri'
    FIELD_SECTOR_IDENTIFIER = 'sector_identifier'
    FIELD_STATUS = 'status'
    FIELD_GRANTS = 'grants'
    FIELD_CONSUMER_SECRET = 'consumer_secret'

    FIELD_STATUS_VALUE_ACTIVE = 'active'

    @classmethod
    def find_one_by_id(cls, client_id, cached=True):
        key = cls.get_cache_key(client_id)

        if cached:
            app = cache.get(key)
            if app is not None:
                logger.debug("Getting app from cache: %s", client_id)
                return app

        app = cls.objects.find_one({cls.FIELD_ID: client_id})

        if app is not None:
            app[cls.FIELD_STATUS] = app.get(cls.FIELD_STATUS, cls.FIELD_STATUS_VALUE_ACTIVE)
            app[cls.FIELD_SECTOR_IDENTIFIER] = cls.get_sector_identifier(app)
            app[cls.FIELD_NAME] = app[cls.FIELD_NAME] if isinstance(app[cls.FIELD_NAME], list) else [app[cls.FIELD_NAME]]

            logger.debug("Saving app in cache: %s", client_id)
            cache.set(key, app)

        return app

    @classmethod
    def get_sector_identifier(cls, app):
        url = app.get(cls.FIELD_SECTOR_IDENTIFIER_URI, app.get(cls.FIELD_REDIRECT_URI, None))
        if url:
            url = url[0] if isinstance(url, list) else url
            p = urlparse(url)
            return p.netloc
        return None

    @classmethod
    def get_cache_key(cls, client_id):
        return f"app_{client_id}"


class UserPcrCollection(BaikalCollection):

    collection_name = 'user_pcrs'

    INDEX_USER_SECTOR = 'user_sector'

    FIELD_PCR = '_id'
    FIELD_USER = 'user'
    FIELD_SECTOR_IDENTIFIER = 'sector_identifier'

    @classmethod
    def get_pcr_or_create(cls, user, sector_identifier):
        pcr = cls.objects.find_one_and_update(
            {
                cls.FIELD_USER: user,
                cls.FIELD_SECTOR_IDENTIFIER: sector_identifier
            },
            {
                '$setOnInsert': {
                    cls.FIELD_PCR: str(uuid4()),
                    cls.FIELD_USER: user,
                    cls.FIELD_SECTOR_IDENTIFIER: sector_identifier
                }
            },
            return_document=ReturnDocument.AFTER,
            upsert=True)

        return pcr[cls.FIELD_PCR]

    @classmethod
    def find_pcr(cls, pcr, sector_identifier, uid):
        return cls.objects.find_one({cls.FIELD_PCR: pcr, cls.FIELD_SECTOR_IDENTIFIER: sector_identifier, cls.FIELD_USER: uid})

    @classmethod
    def ensure_all_indexes(cls):
        try:
            logger.info('Creating user pcr indexes...')
            super().ensure_indexes([
                {'name': cls.INDEX_USER_SECTOR, 'keys': [(cls.FIELD_USER, pymongo.ASCENDING), (cls.FIELD_SECTOR_IDENTIFIER, pymongo.ASCENDING)], 'unique': True}
            ])
            logger.info('User pcr indexes created')
        except Exception as e:
            logger.error('Unable to create user pcr indexes: %s', str(e.args[0]))


class Grant:

    FIELD_GRANT_TYPE = 'grant_type'
    FIELD_SCOPES = 'scopes'
    FIELD_CLAIMS = 'claims'
    FIELD_ACCESS_TOKEN_TTL = 'access_token_ttl'
    FIELD_REFRESH_TOKEN_TTL = 'refresh_token_ttl'
