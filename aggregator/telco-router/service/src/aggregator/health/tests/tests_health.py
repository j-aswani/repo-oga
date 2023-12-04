from django.test.client import Client

from aggregator.utils.tests.base import AggregatorTestCase


class HealthCheckTestCase(AggregatorTestCase):

    def test_check_health(self):
        c = Client()
        response = c.get('/health/check')
        self.assertEqual(response.status_code, 200)
