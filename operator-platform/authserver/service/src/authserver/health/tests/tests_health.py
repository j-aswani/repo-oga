from django.test.client import Client

from authserver.utils.tests.base import AuthserverTestCase


class HealthCheckTestCase(AuthserverTestCase):

    def test_check_health(self):
        c = Client()
        response = c.get('/health/check')
        self.assertEqual(response.status_code, 200)
