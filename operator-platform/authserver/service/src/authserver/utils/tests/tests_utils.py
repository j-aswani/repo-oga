import copy
from datetime import datetime

from django.conf import settings
from django.test.utils import override_settings
from freezegun.api import freeze_time

from authserver.utils.tests.base import AuthserverTestCase
from authserver.utils.utils import Singleton, get_key, get_cleaned_data, \
    censor_value, get_iso8601_date, remove_tel_prefix, to_epoch, dot, undot, uncapitalize_first, capitalize_first, enrich_object, censor_form_urlencoded_str, censor_obj_str


class SingletonTestClass(metaclass=Singleton):

    def __init__(self):
        super().__init__()


class TestSingleton(AuthserverTestCase):

    def test_singleton(self):
        s1 = SingletonTestClass()
        s2 = SingletonTestClass()
        self.assertTrue(s1 is s2)


class TestDict(AuthserverTestCase):

    d = {
        'foo': 'bar',
        'test': {
            'foo': 12345678,
            'bar': 2,
            'test': [1, 2]
        }
    }

    def test_get_key(self):
        self.assertEqual(get_key('foo', self.d), 'bar')
        self.assertEqual(get_key(['foo'], self.d), 'bar')
        self.assertEqual(get_key(['test', 'foo'], self.d), 12345678)

        # Exceptions
        with self.assertRaises(KeyError):
            get_key('bar', self.d)
        with self.assertRaises(KeyError):
            get_key(['bar'], self.d)
        with self.assertRaises(KeyError):
            get_key(['bar', 'bar'], self.d)
        with self.assertRaises(KeyError):
            get_key(['bar', 'test'], self.d)


class TestCensorer(AuthserverTestCase):

    d = {
        'foo': 'bar',
        'test': {
            'foo': 12345678,
            'bar': 2,
            'test': [1, 2]
        },
        'secret': 'mysecret'
    }

    @override_settings(CENSORER_MASKED_FIELDS={'foo', 'secret'}, CENSORER_FULL_MASKED_FIELDS={'secret'}, DEBUG=False)
    def test_clean_censored(self):
        d1 = copy.deepcopy(self.d)
        d2 = get_cleaned_data(d1)
        self.assertFalse(d1 == d2)

        self.assertNotEqual(d1['foo'], d2['foo'])
        self.assertTrue(d2['foo'].startswith(settings.CENSORER_MASK))
        self.assertFalse(d2['foo'].endswith('bar'))
        self.assertNotEqual(d1['test']['foo'], d2['test']['foo'])
        self.assertTrue(d2['test']['foo'].startswith(settings.CENSORER_MASK))
        self.assertFalse(d2['test']['foo'].endswith('12345678'))

        self.assertNotEqual(d1['secret'], d2['secret'])
        self.assertEqual(d2['secret'], settings.CENSORER_MASK)

    @override_settings(CENSORER_MASKED_FIELDS={'hello'}, DEBUG=False)
    def test_clean_no_censored(self):
        d1 = copy.deepcopy(self.d)
        d2 = get_cleaned_data(d1)
        self.assertFalse(d1 is d2)
        self.assertDictEqual(d1, d2)

    @override_settings(CENSORER_MASKED_FIELDS={'foo'}, DEBUG=True)
    def test_clean_debugging(self):
        d1 = copy.deepcopy(self.d)
        d2 = get_cleaned_data(d1)
        self.assertTrue(d1 is d2)

    def test_censorer(self):
        self.assertEqual(censor_value('12345678'), '----5678')
        self.assertEqual(censor_value(12345678), '----5678')
        self.assertEqual(censor_value(1), '----')

        self.assertEqual(censor_value(['12345678', 'abcdef']), ['----5678', '----cdef'])

    @override_settings(CENSORER_NUM_UNMASKED_CHARS=0, CENSORER_MASK='-----')
    def test_censorer_uncensored(self):
        self.assertEqual(censor_value('12345678'), '-----')
        self.assertEqual(censor_value(1), '-----')

    @override_settings(CENSORER_FULL_MASKED_FIELDS={'foo'}, DEBUG=False)
    def test_obj_str_censored(self):
        self.assertEqual(censor_obj_str('{"foo": 1, "bar": 2}'), '{"foo":"----","bar":2}')
        self.assertEqual(censor_obj_str('[{"foo": 1, "bar": 2},{"foo": 3, "bar": 4}]'), '[{"foo":"----","bar":2},{"foo":"----","bar":4}]')
        self.assertIsNone(censor_obj_str(None))
        with self.assertRaises(ValueError):
            censor_obj_str('{"foo"')

    @override_settings(CENSORER_FULL_MASKED_FIELDS={'foo'}, DEBUG=False)
    def test_form_urlencoded_str_censored(self):
        self.assertEqual(censor_form_urlencoded_str('foo=1&bar=2'), 'foo=----&bar=2')
        self.assertIsNone(censor_form_urlencoded_str(None))
        with self.assertRaises(ValueError):
            censor_form_urlencoded_str('a')


class TestString(AuthserverTestCase):

    def test_capitalize_first(self):
        self.assertEqual(capitalize_first('Foo Bar'), 'Foo Bar')
        self.assertEqual(capitalize_first('foo Bar'), 'Foo Bar')
        self.assertIsNone(capitalize_first(None))
        self.assertEqual(capitalize_first(''), '')

    def test_uncapitalize_first(self):
        self.assertEqual(uncapitalize_first('Foo Bar'), 'foo Bar')
        self.assertEqual(uncapitalize_first('foo Bar'), 'foo Bar')
        self.assertIsNone(uncapitalize_first(None))
        self.assertEqual(uncapitalize_first(''), '')

    def test_dot(self):
        self.assertEqual(dot('foo Bar'), 'foo Bar.')
        self.assertEqual(dot('foo Bar.'), 'foo Bar.')
        self.assertIsNone(dot(None))
        self.assertEqual(dot(''), '')

    def test_undot(self):
        self.assertEqual(undot('foo Bar.'), 'foo Bar')
        self.assertEqual(undot('foo Bar'), 'foo Bar')
        self.assertIsNone(undot(None))
        self.assertEqual(undot(''), '')


class TestDate(AuthserverTestCase):

    @freeze_time('2017-09-21 01:02:03.456', tz_offset=0)
    def test_iso8601_now(self):
        self.assertEqual('2017-09-21T01:02:03.456Z', get_iso8601_date())

    @freeze_time('2017-09-21 01:02:03.456', tz_offset=0)
    def test_iso8601_date(self):
        self.assertEqual('2017-09-21T01:02:03.456Z', get_iso8601_date(datetime.now()))

    def test_iso8601_int(self):
        self.assertEqual('2017-09-10T00:35:01.000Z', get_iso8601_date(1505003701))

    def test_iso8601_str(self):
        self.assertEqual('2017-03-02T08:31:54.318Z', get_iso8601_date('2017-03-02T09:31:54.318+01:00'))

    def test_iso8601_delta(self):
        self.assertEqual('2017-03-02T08:32:04.318Z', get_iso8601_date('2017-03-02T09:31:54.318+01:00', 10))

    @freeze_time('2017-09-21 01:02:03.456', tz_offset=0)
    def test_epoch(self):
        self.assertEqual(1505955723.456, to_epoch(datetime.now()))


class TestTelephonePrefix(AuthserverTestCase):

    def test_tel_prefix(self):
        self.assertEqual(remove_tel_prefix('tel:+123456789'), '+123456789')


class TestObject(AuthserverTestCase):

    def test_enric_object(self):
        obj = type('', (), {'foo': 1})
        self.assertEqual(obj.foo, 1)
        enrich_object(obj, {'foo': 2, 'bar': '3'})
        self.assertEqual(obj.foo, 2)
        self.assertEqual(obj.bar, '3')
