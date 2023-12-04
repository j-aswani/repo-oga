from django.test.client import Client

from aggregator.utils.tests.base import AggregatorTestCase


class Test404(AggregatorTestCase):

    client = Client()

    def test_get(self):
        response = self.client.get('/foo')
        self.assert404(response)

    def test_post(self):
        response = self.client.post('/foo')
        self.assert404(response)

    def test_put(self):
        response = self.client.put('/foo')
        self.assert404(response)

    def test_delete(self):
        response = self.client.delete('/foo')
        self.assert404(response)

    def assert404(self, response):
        self.assertEqual(response.status_code, 404)
