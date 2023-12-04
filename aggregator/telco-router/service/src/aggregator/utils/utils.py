import base64
import copy
import functools
import hashlib
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode

import dateutil
import ujson as json
from django.conf import settings


class Singleton(type):

    def __init__(self, name, bases, dct):
        self.__instance = None
        type.__init__(self, name, bases, dct)

    def __call__(self, *args, **kw):
        if self.__instance is None:
            self.__instance = type.__call__(self, *args, **kw)
        return self.__instance

    def _drop(self):
        # Drop the instance (for testing purposes).
        del self._Singleton__instance
        self.__instance = None


def censor_value(value):

    def censor_str(value):
        if len(value) <= settings.CENSORER_NUM_UNMASKED_CHARS or settings.CENSORER_NUM_UNMASKED_CHARS == 0:
            return settings.CENSORER_MASK
        else:
            return settings.CENSORER_MASK + value[-settings.CENSORER_NUM_UNMASKED_CHARS:]

    if isinstance(value, list):
        return list(map(censor_str, value))
    return censor_str(str(value))


def censor_obj_str(value):
    if value is not None:
        obj = json.loads(value)
        if isinstance(obj, dict):
            return json.dumps(get_cleaned_data(obj))
        elif isinstance(obj, list):
            return json.dumps(list(map(get_cleaned_data, obj)))
    return value


def censor_form_urlencoded_str(value):
    if value is not None:
        return urlencode(get_cleaned_data(dict(parse_qsl(value, keep_blank_values=True, strict_parsing=True))))
    return value


def clean_dictionary(value):
    if isinstance(value, dict):
        for k, v in value.items():
            if k in settings.CENSORER_FULL_MASKED_FIELDS:
                value[k] = settings.CENSORER_MASK
            elif k in settings.CENSORER_MASKED_FIELDS:
                value[k] = censor_value(value[k])
            elif isinstance(v, dict):
                clean_dictionary(v)
            elif isinstance(v, list):
                for d in v:
                    clean_dictionary(d)


def get_cleaned_data(data_dict):
    new_data_dict = data_dict
    if not settings.DEBUG:
        new_data_dict = copy.deepcopy(data_dict)
        clean_dictionary(new_data_dict)
    return new_data_dict


def get_key(keys, obj):
    try:
        if not isinstance(keys, list):
            keys = [keys]
        return functools.reduce(lambda d, k: d[k], keys, obj)
    except Exception:
        raise KeyError(keys)


def get_iso8601_date(date=None, delta_seconds=None):
    if date is None:
        date = datetime.utcnow()
    elif isinstance(date, str):
        date = dateutil.parser.parse(date)
    elif isinstance(date, int):
        date = datetime.fromtimestamp(date, tz=timezone.utc)
    if delta_seconds is not None:
        date = date + timedelta(seconds=delta_seconds)

    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)

    return date.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def to_epoch(date):
    if date.tzinfo is None:
        date = date.replace(tzinfo=timezone.utc)
    return date.timestamp()


def capitalize_first(s):
    if s is not None and len(s) > 0:
        s = s[0].upper() + s[1:]
    return s


def uncapitalize_first(s):
    if s is not None and len(s) > 0:
        s = s[0].lower() + s[1:]
    return s


def dot(s):
    if s is not None and len(s) > 0:
        s = s if s[-1] == '.' else s + '.'
    return s


def undot(s):
    if s is not None and len(s) > 0:
        s = s if s[-1] != '.' else s[:-1]
    return s


def hash_value(value):
    hash_sha256 = hashlib.sha256()
    hash_sha256.update(value.encode('ascii'))
    digest = hash_sha256.digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')


def remove_tel_prefix(msisdn):
    if msisdn is not None:
        return msisdn.removeprefix('tel:')
    return None


def overwrite_dict(dictionary, values):
    for k, v in values.items():
        if v is None:
            if k in dictionary:
                del dictionary[k]
        else:
            dictionary[k] = v


def enrich_object(obj, dictionary):
    for k, v in dictionary.items():
        setattr(obj, k, v)
