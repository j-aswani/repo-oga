from authserver.utils.database import CollectionClass, DBClient, DBException
from authserver.utils.tests.base import AuthserverTestCase


class CollectionError(object, metaclass=CollectionClass):

    @classmethod
    def test_objects(cls):
        return cls.objects.find_one({'foo': 'bar'})


class MisconfiguredDataBaseClient(DBClient):
    options = {
        'default': {
            'host': 'foo://foo:3333/bar'
        }
    }
    connections = {}


class MisconfiguredDataBaseCollectionError(CollectionError):
    collection_name = 'test'
    db_client = MisconfiguredDataBaseClient


class TestDatabase(AuthserverTestCase):

    def test_db_client_error(self):
        client = DBClient()
        self.assertRaisesRegex(DBException, 'No database options defined',
                               client.get_connection, 'foo')

    def test_db_collection_class_error(self):
        self.assertRaisesRegex(DBException, 'No database client defined',
                               CollectionError.test_objects)

        CollectionError.db_client = DBClient

        self.assertRaisesRegex(DBException, 'No database name defined',
                               CollectionError.test_objects)

        CollectionError.database = 'default'

        self.assertRaisesRegex(DBException, 'No collection name defined',
                               CollectionError.test_objects)

    def test_db_misconfigured_database_error(self):
        self.assertRaisesRegex(DBException, 'Misconfigured database',
                               MisconfiguredDataBaseCollectionError.test_objects)
