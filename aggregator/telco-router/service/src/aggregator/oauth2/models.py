import calendar
import logging
from datetime import datetime
from urllib.parse import urlparse

import pymongo
from django.conf import settings
from django.core.cache import cache

from aggregator.utils.database import AggregatorCollection

logger = logging.getLogger(settings.LOGGING_PREFIX)


class JtiCollection(AggregatorCollection):

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
    def find_jti(cls, client_id, jti):
        jti = cls.objects.find_one({cls.FIELD_CLIENT_ID: client_id, cls.FIELD_JTI: jti})
        if jti is not None:
            if calendar.timegm(datetime.timetuple(datetime.utcnow())) > calendar.timegm(datetime.timetuple(jti[cls.FIELD_EXPIRATION])):
                return None
        return jti

    @classmethod
    def insert_jti(cls, client_id, jti, expiration):
        return cls.objects.insert_one({cls.FIELD_CLIENT_ID: client_id, cls.FIELD_JTI: jti, cls.FIELD_EXPIRATION: expiration})


class ApplicationCollection(AggregatorCollection):

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
        url = app.get(cls.FIELD_SECTOR_IDENTIFIER_URI, app[cls.FIELD_REDIRECT_URI])
        url = url[0] if isinstance(url, list) else url
        p = urlparse(url)
        return p.netloc

    @classmethod
    def get_cache_key(cls, client_id):
        return f"app_{client_id}"


class Grant:

    FIELD_GRANT_TYPE = 'grant_type'
    FIELD_SCOPES = 'scopes'
    FIELD_CLAIMS = 'claims'
    FIELD_ACCESS_TOKEN_TTL = 'access_token_ttl'
    FIELD_REFRESH_TOKEN_TTL = 'refresh_token_ttl'
