from resolvers.resolver import IdentifierResolver


class DummyMsisdnResolver(IdentifierResolver):

    def get_operator(self, identifier_value):
        return "TELEFONICA"
