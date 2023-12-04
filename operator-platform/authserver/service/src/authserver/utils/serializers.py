from rest_framework import serializers

from authserver.utils.utils import get_iso8601_date


class DateTimeField(serializers.DateTimeField):  # pragma: no cover

    def to_representation(self, value):
        if not value:
            return None

        return get_iso8601_date(value)

