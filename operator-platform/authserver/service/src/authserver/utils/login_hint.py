from authserver.utils.exceptions import ServerErrorException, InvalidParameterValueError
from authserver.utils.schemas import FIELD_IDENTIFIER, FIELD_IDENTIFIER_TYPE

LOGIN_HINT_TRANSLATOR = {
    'tel:+': lambda value: {FIELD_IDENTIFIER: value.removeprefix('tel:'), FIELD_IDENTIFIER_TYPE: 'phone_number'},
    'phone_number:': lambda value: {FIELD_IDENTIFIER: value.removeprefix('phone_number:'), FIELD_IDENTIFIER_TYPE: 'phone_number'},
    'ip': lambda value: {FIELD_IDENTIFIER: value.removeprefix('ip:'), FIELD_IDENTIFIER_TYPE: 'ip'},
    'ipport': lambda value: {FIELD_IDENTIFIER: value.removeprefix('ip:'), FIELD_IDENTIFIER_TYPE: 'ip'}
}


def get_login_hint_obj(value):
    try:
        for prefix, func in LOGIN_HINT_TRANSLATOR.items():
            if value.startswith(prefix):
                return func(value)
    except ServerErrorException as e:
        raise e
    except Exception as e:
        raise InvalidParameterValueError('login_hint', str(e.args[0]))

    raise InvalidParameterValueError('login_hint', 'Invalid prefix')
