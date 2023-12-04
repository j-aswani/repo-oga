from django.conf import settings
from rest_framework.response import Response
from rest_framework.status import HTTP_200_OK

from authserver.utils.exceptions import MissingParameterError, InvalidParameterValueError
from authserver.utils.renderers import JRDJSONRenderer
from authserver.utils.views import publish_to_middleware, JSONBasicAuthenticatedView


@publish_to_middleware(response_content_type='application/json', operation='WEBFINGER')
class WebFingerView(JSONBasicAuthenticatedView):

    renderer_classes = (JRDJSONRenderer,)

    scopes = ['telcofinder']

    def get(self, request):

        if 'resource' not in request.GET:
            raise MissingParameterError('resource')
        elif len(request.GET.getlist('resource')) > 1:
            raise InvalidParameterValueError('resource', 'Multiple values are not allowed')

        # In multi-branding scenario. endpoints and properties could be different for each brand.
        # Thus, an internal call to resolve the brand should be needed.
        # For now, we assume that all brands have the same endpoints and properties.
        links = [
            {
                "rel": "http://openid.net/specs/connect/1.0/issuer",
                "href": settings.AUTHSERVER_ISSUER
            },
            {
                "rel": "apis",
                "href": settings.API_HOST
            }
        ]

        if 'rel' in request.query_params:
            links = [link for link in links if link['rel'] in request.GET.getlist('rel')]

        claims = {
            "subject": request.query_params['resource'],
            "properties": {
                "operator_id": settings.OPERATOR_ID
            },
            "links": links
        }

        return Response(claims, HTTP_200_OK)
