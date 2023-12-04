from authserver.utils.exceptions import InvalidParameterValueError
from authserver.utils.login_hint import get_login_hint_obj
from authserver.utils.tests.base import AuthserverTestCase


class TestLoginHint(AuthserverTestCase):

    def test_login_hint_object(self):
        tests = [
            ('tel:+34618051526', 'phone_number', '+34618051526'),
            ('phone_number:+34618051526', 'phone_number', '+34618051526'),
            ('ip:127.0.0.1', 'ip', '127.0.0.1')
        ]
        for value, identifier_type, identifier in tests:
            self.assertDictEqual(get_login_hint_obj(value), {'identifier_type': identifier_type, 'identifier': identifier})

    def test_invalid_prefix(self):

        with self.assertRaisesRegex(InvalidParameterValueError, 'Invalid login_hint parameter value: Invalid prefix.'):
            get_login_hint_obj('foo:bar')
