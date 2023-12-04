from django import template
from django.conf import settings
from django.templatetags.static import static

register = template.Library()


@register.simple_tag
def version():
    static_version = getattr(settings, 'STATIC_VERSION', '')
    if static_version:
        return 'v=' + static_version
    return ''


@register.simple_tag
def vstatic(path):
    url = static(path)
    v = version()
    if v:
        url += '?' + v
    return url
