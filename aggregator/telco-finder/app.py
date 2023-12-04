from logging.config import dictConfig

from flask import Flask, jsonify, request, make_response
from gevent.pywsgi import WSGIServer

from exceptions import TelcoFinderException, ServerErrorException, InvalidRequestException, NotFoundException
from resolvers.resolver import OperatorResolver
from settings import PORT, OPERATOR_DATABASE
from telco import OperatorClient

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '{"time":"%(asctime)s","lvl":"%(levelname)s","msg":"%(message)s"}',
        'datefmt': '%Y-%m-%dT%H:%M:%S%z'
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://sys.stdout',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)

#Initialize identifier resolvers
operator_resolver = OperatorResolver()


@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, TelcoFinderException):
        app.logger.warning('Handled error %s (%s)', e.error, e.description)
        return jsonify({'error': e.error, 'error_description': e.description}), e.status_code
    elif isinstance(e, ValueError):
        return handle_exception(InvalidRequestException(f'Invalid identifier value: {e.args[0]}'))
    else:
        app.logger.error('Internal server error', exc_info=True)
        return handle_exception(ServerErrorException())


# Telco Finder
#
# Each aggregator is able to resolve the serving operator for a given identifier
# passed in the request. The identifier might be an IP address and port, a MSISDN,
# or any other kind of subscriber identifier.
#
# This is a simplified example that only supports IP addresses as identifiers.
#
#
@app.route('/.well-known/webfinger', methods=['GET'])
def webfinger():
    resource = request.args.get('resource')
    identifier_type, identifier_value = get_identifier(resource)

    operator_id = operator_resolver.get_operator_by_identifier(identifier_type, identifier_value)
    if operator_id is None:
        raise NotFoundException('Not able to resolve serving operator')

    app.logger.info('Resolved operator %s for identifier %s', operator_id, identifier_value)

    info = get_operator_info(operator_id, resource, request.args.getlist('rel'))
    if info is None:
        raise NotFoundException('Not able to resolve serving operator')

    r = make_response(info)
    r.mimetype = 'application/jrd+json'
    return r


def get_identifier(resource):
    if resource is None:
        raise InvalidRequestException('Resource parameter is mandatory')
    resource_parts = resource.split(':')
    if len(resource_parts) < 1:
        raise InvalidRequestException('Invalid format for resource parameter')
    identifier_value = ':'.join(resource_parts[1:])
    if len(identifier_value) ==0:
        raise InvalidRequestException('Identifier value cannot be empty in resource parameter')
    return resource_parts[0], identifier_value


# In an alternative scenario, this information could be retrieved from a database
# In this implementation the information comes from the operator's webfinger service
def get_operator_info(operator_id, resource, rels):
    params = [
        ('resource', resource)
    ]
    if rels is not None and len(rels) > 0:
        for rel in rels:
            params.append(('rel', rel))
    return OperatorClient().webfinger(OPERATOR_DATABASE[operator_id], params)


@app.route('/healthz')
def healthz():
    return 'OK'


if __name__ == '__main__':
    http_server = WSGIServer(('0.0.0.0', PORT), app)
    http_server.serve_forever()
