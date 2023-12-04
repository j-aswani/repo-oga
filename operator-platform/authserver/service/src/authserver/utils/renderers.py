from rest_framework.renderers import JSONRenderer

class JRDJSONRenderer(JSONRenderer):
    media_type = 'application/jrd+json'