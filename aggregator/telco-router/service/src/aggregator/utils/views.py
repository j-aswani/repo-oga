from django.utils.decorators import classonlymethod
from django.views.generic.base import View

from .exceptions import NotFoundError


class Handler404(View):

    def dispatch(self, request, *args, **kwargs):
        raise NotFoundError(request.path)


def publish_to_middleware(**kwargs):

    def wrapper(class_view):

        def as_view(cls, **initkwargs):
            view = super(cls, cls).as_view(**initkwargs)
            for k, v in kwargs.items():
                setattr(view, k, v)
            return view

        return type(class_view.__name__, (class_view,), {
            'as_view': classonlymethod(as_view),
        })

    return wrapper
