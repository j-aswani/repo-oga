from django.conf import settings


def branding(request):
    return {'branding': settings.BRANDING}
