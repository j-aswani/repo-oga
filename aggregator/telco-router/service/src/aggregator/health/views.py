from django.http.response import HttpResponse
from django.views.generic.base import View

from aggregator.oauth2.models import ApplicationCollection


class CheckView(View):

    def get(self, request):
        _ = ApplicationCollection.objects.find_one({ApplicationCollection.FIELD_ID: '__health__'})
        return HttpResponse(status=200)
