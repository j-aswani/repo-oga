import logging

from exceptions import InvalidRequestException
from settings import OPERATOR_RESOLVERS
from utils import Singleton, load_class

logger = logging.getLogger()


class IdentifierResolver(object):

    def get_operator(self, identifier_value):
        """
        Get Operator ID from identifier value.
        :param str identifier_value: The identifier value of the user
        :return: the operator id, None value if it cannot be resolved by identifier_value
        :raises ValueError: if identifier_value is invalid or malformed
        """
        raise NotImplementedError()


class OperatorResolver(object, metaclass=Singleton):

    def __init__(self):
        self.resolvers = {}
        logger.info('Loading operator resolvers')
        for k, v in OPERATOR_RESOLVERS.items():
            logger.info('Loading operator resolver %s->%s...', k, v)
            self.resolvers[k] = load_class(v)
            logger.info('Loaded operator resolver %s->%s', k, v)

    def get_operator_by_identifier(self, identifier_type, identifier_value):
        if identifier_type not in self.resolvers:
            raise InvalidRequestException(f'Unsupported identifier_type {identifier_type}')
        return self.resolvers[identifier_type].get_operator(identifier_value)
