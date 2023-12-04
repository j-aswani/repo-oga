import copy
import logging

from django.conf import settings
from pymongo.errors import ConfigurationError, AutoReconnect, ConnectionFailure
from pymongo.mongo_client import MongoClient

from .utils import Singleton

logger = logging.getLogger(settings.LOGGING_PREFIX)


class DBException(Exception):
    pass


class DBClient(object, metaclass=Singleton):
    options = settings.MONGO_DATABASE_OPTIONS
    connections = {}

    def get_connection(self, database):
        try:
            if database not in self.connections:
                if self.options is None:
                    raise DBException('No database options defined')
                if database not in self.options:
                    raise DBException(f'No database options defined for {database}')
                self.connections[database] = MongoClient(connect=True, **self.options[database])
            return self.connections[database]
        except ConfigurationError as e:
            logger.error('Error in database configuration: %s', str(e.args[0]))
            raise DBException(f'Misconfigured database {database}')
        except (AutoReconnect, ConnectionFailure) as e:  # pragma: no cover
            logger.error('Error getting database connection: %s', str(e.args[0]))
            raise DBException(f'Database {database} is not available')


class CollectionClass(type):

    """Database document definition.
        :Attributes:
          - `database`: the database to get a collection from
          - `collection_name`: the name of the collection to get
          - `objects`: get/create a Mongo collection
    """

    db_client = None
    collection_name = None
    database = None

    @classmethod
    def get_collection(cls, db_client, database, collection_name):
        connection = db_client().get_connection(database)
        return getattr(connection.get_default_database(), collection_name)

    @property
    def objects(self):
        if self.db_client is None:
            raise DBException('No database client defined')
        if self.database is None:
            raise DBException('No database name defined')
        if self.collection_name is None:
            raise DBException('No collection name defined')
        return self.get_collection(self.db_client, self.database, self.collection_name)


class AggregatorCollection(object, metaclass=CollectionClass):
    db_client = DBClient
    database = 'default'
    collection_name = None

    @classmethod
    def ensure_indexes(cls, indexes):

        def indexes_equal(mongo, creation):
            mongo_clean = copy.deepcopy(mongo)
            creation_clean = copy.deepcopy(creation)
            del creation_clean['name']
            mongo_clean['keys'] = mongo_clean.pop('key')
            for field in ['v', 'ns']:
                try:
                    del mongo_clean[field]
                except KeyError:
                    pass

            return mongo_clean == creation_clean

        try:
            current_indexes = cls.objects.index_information()
        except Exception:
            current_indexes = {}

        for index in indexes:
            if 'name' not in index:
                raise DBException('No name field in index creation')

            if index['name'] not in current_indexes:
                logger.info('Creating index: %s',  index['name'])
                cls.objects.create_index(**index)
            elif not indexes_equal(current_indexes[index['name']], index):
                logger.info('Dropping existing index with different configuration: %s',  index['name'])
                cls.objects.drop_index(index['name'])
                logger.info('Creating index: %s',  index['name'])
                cls.objects.create_index(**index)
            else:
                logger.info('Index already exists: %s',  index['name'])

        # Remove unused indexes
        unused = set(current_indexes.keys()) - set([x['name'] for x in indexes]) - {'_id_'}
        for u in unused:
            logger.info('Dropping unused index: %s',  u)
            cls.objects.drop_index(u)
