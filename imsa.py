#!/usr/bin/env python
import argparse
import datetime
import functools
import inspect
import logging
import logging.handlers
import os
import sys
import threading
import wsgiref.simple_server

import argcomplete
import boto3
import botocore.exceptions
import pyramid.config
import pyramid.response
import pyramid.view
import requests
import yaml

logger = logging.getLogger(__name__)


LOG_FORMAT = '%(asctime)s - %(levelname)7s - %(name)s - %(message)s'

CONFIG_PATH = os.path.expanduser('~/.imsa')

IP_ADDRESS = '169.254.169.254'
INVALID_CREDENTIAL_PATH = '/latest/meta-data/iam/security-credentials'
CREDENTIAL_PATH = INVALID_CREDENTIAL_PATH + '/'
DUMMY_ROLE = 'imsa'
CONTROL_PATH = '/__imsa/%s/'

MINIMUM_MINUTES_IN_SESSION = 5

HELP_STRINGS = ['-h', '--h', '--he', '--hel', '--help']


def main():
    arguments = __get_arguments()
    arguments.function(arguments)


def __load_config():
    with open(CONFIG_PATH, 'r') as file_object:
        return yaml.load(file_object)


def __get_arguments():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(
        title='Available commands',
        dest='command',
    )
    subparsers.required = True

    __add_start_parser(subparsers)
    __add_stop_parser(subparsers)
    __add_assume_parser(subparsers)

    argcomplete.autocomplete(parser)
    return parser.parse_args()


def __add_start_parser(parser):
    start_parser = parser.add_parser('start')
    start_parser.set_defaults(function=server_start)
    __add_common_arguments(start_parser)

    start_parser.add_argument(
        '--log-file',
        help='Log to this file instead of the command line',
    )


def __add_stop_parser(parser):
    stop_parser = parser.add_parser('stop')
    stop_parser.set_defaults(function=client_stop)
    __add_common_arguments(stop_parser)


def __add_assume_parser(parser):
    assume_parser = parser.add_parser('assume')
    __add_common_arguments(assume_parser)

    profile_argument = assume_parser.add_argument('profile')

    is_help_call = any([string in sys.argv for string in HELP_STRINGS])
    # config should only be loaded for assume, not the other commands
    # parse_known_args would break argcomplete and help
    if len(sys.argv) > 1 and sys.argv[1] == 'assume' or is_help_call:
        config = __load_config()
        choices = sorted(config.keys())

        profile_argument.choices = choices

        function = functools.partial(client_assume, config)
        assume_parser.set_defaults(function=function)

    # need to add this completer as choices is not available during completion
    profile_argument.completer = __profile_completer


def __profile_completer(**_kwargs):
    return sorted(__load_config().keys())


def __add_common_arguments(parser):
    parser.add_argument(
        '--port',
        default=80,
        type=int,
    )


class LoggingWSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):

    # pylint: disable=redefined-builtin
    def log_message(self, format, *args):
        logger.info(' '.join([self.client_address[0], *args]))


def server_start(arguments):
    try:
        __configure_logging(arguments)
        with pyramid.config.Configurator() as config:
            __discover_routes(config)
            # configure exception_view_config
            config.scan()
            app = config.make_wsgi_app()

        logger.info('Start server')
        server = wsgiref.simple_server.make_server(
            IP_ADDRESS,
            arguments.port,
            app,
            handler_class=LoggingWSGIRequestHandler,
        )
        State.get_instance().server = server
        logger.info('Accept requests')
        server.serve_forever()
    except Exception:
        logger.exception('Error starting server')


def __configure_logging(arguments):
    if arguments.log_file:
        handler = logging.handlers.RotatingFileHandler(
            arguments.log_file,
            maxBytes=5120,
            backupCount=5,
        )
        handlers = [handler]
    else:
        handlers = None

    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        handlers=handlers,
    )


def __register_route(route):
    def wrapper(fun):
        fun.route = route
        return fun
    return wrapper


def __discover_routes(config):
    for name, object_ in inspect.getmembers(sys.modules[__name__]):
        if inspect.isfunction(object_) and hasattr(object_, 'route'):
            config.add_route(name, object_.route)
            config.add_view(object_, route_name=name)


class State():

    def __init__(self):
        self.server = None
        self.profile_config = {}
        self.session_credentials = {}
        self.role_credentials = {}

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = State()
        return cls.instance

    def is_session_valid(self):
        if not self.session_credentials:
            return False

        if self.__have_credentials_expired(self.session_credentials):
            return False

        return True

    def __have_credentials_expired(self, credentials):
        now = datetime.datetime.utcnow()
        soon = now + datetime.timedelta(minutes=MINIMUM_MINUTES_IN_SESSION)
        expiration = credentials['Expiration'].replace(tzinfo=None)
        return expiration < soon

    def update_session_credentials(self):
        logger.info('Update session credentials')
        client = boto3.client(
            'sts',
            aws_access_key_id=self.profile_config['aws_access_key_id'],
            aws_secret_access_key=self.profile_config['aws_secret_access_key'],
            region_name=self.profile_config['region_name'],
        )
        response = client.get_session_token(
            SerialNumber=self.profile_config['mfa_serial_number'],
            TokenCode=self.profile_config['mfa_token_code'],
        )
        self.session_credentials = response['Credentials']
        self.session_credentials['LastUpdated'] = datetime.datetime.utcnow()

    def update_role_credentials(self):
        logger.info('Update role credentials')
        client = boto3.client(
            'sts',
            aws_access_key_id=self.session_credentials['AccessKeyId'],
            aws_secret_access_key=self.session_credentials['SecretAccessKey'],
            aws_session_token=self.session_credentials['SessionToken'],
        )
        response = client.assume_role(
            RoleArn=self.profile_config['role_arn'],
            RoleSessionName=self.profile_config['role_session_name'],
        )
        self.role_credentials = response['Credentials']
        self.role_credentials['LastUpdated'] = datetime.datetime.utcnow()

    def maybe_update_role_credentials(self):
        if not self.role_credentials:
            return
        if self.__have_credentials_expired(self.role_credentials):
            self.update_role_credentials()


@__register_route(INVALID_CREDENTIAL_PATH)
def server_get_role_one(_request):
    return pyramid.httpexceptions.HTTPMovedPermanently(CREDENTIAL_PATH)


@__register_route(CREDENTIAL_PATH)
def server_get_role_two(_request):
    return pyramid.response.Response(DUMMY_ROLE)


@__register_route(CREDENTIAL_PATH + DUMMY_ROLE)
def server_get_credentials(_request):
    try:
        state = State.get_instance()
        state.maybe_update_role_credentials()
        credentials = state.role_credentials or state.session_credentials
        if not credentials:
            return pyramid.httpexceptions.HTTPNotFound('No role assumed')
        return pyramid.response.Response(json=__make_response_dict(credentials))
    except botocore.exceptions.ClientError as exception:
        error_message = exception.response['Error']['Message']
        logger.warning(error_message)
        return pyramid.httpexceptions.HTTPNotFound(error_message)
    except Exception:
        logger.exception('Error getting credentials')
        return pyramid.httpexceptions.HTTPInternalServerError()


def __make_response_dict(credentials):
    return {
        'AccessKeyId': credentials['AccessKeyId'],
        'Code': 'Success',
        'Expiration': __format_datetime(credentials['Expiration']),
        'LastUpdated': __format_datetime(credentials['LastUpdated']),
        'SecretAccessKey': credentials['SecretAccessKey'],
        'Token': credentials['SessionToken'],
        'Type': 'AWS-HMAC',
    }


def __format_datetime(datetime_object):
    cleaned = datetime_object.replace(microsecond=0, tzinfo=None)
    return cleaned.isoformat('T') + 'Z'


@__register_route(CONTROL_PATH % 'stop')
def server_stop(_request):
    logger.info('Stop server')
    try:
        server = State.get_instance().server
        threading.Thread(target=server.shutdown).start()
        return pyramid.response.Response()
    except Exception:
        logger.exception('Error stopping server')
        return pyramid.httpexceptions.HTTPInternalServerError()


@__register_route(CONTROL_PATH % 'assume')
def server_assume(request):
    try:
        state = State.get_instance()
        profile_config = request.json
        state.profile_config = profile_config

        if not state.is_session_valid():
            if 'mfa_token_code' not in profile_config:
                return pyramid.httpexceptions.HTTPBadRequest('MFA missing')
            state.update_session_credentials()
        state.update_role_credentials()
        return pyramid.response.Response()
    except Exception:
        logger.exception('Error assuming role')
        return pyramid.httpexceptions.HTTPInternalServerError()


@pyramid.view.exception_view_config(Exception)
def server_exception(_exc, _request):
    logger.exception('Caught an exception that caused an internal server error')
    return pyramid.httpexceptions.HTTPInternalServerError()


def client_stop(arguments):
    address = ':'.join([IP_ADDRESS, str(arguments.port)])
    requests.post(
        'http://' + address + CONTROL_PATH % 'stop',
    )


def client_assume(config, arguments):
    address = ':'.join([IP_ADDRESS, str(arguments.port)])
    url = 'http://' + address + CONTROL_PATH % 'assume'

    profile_config = {}
    profile_config.update(config['default'])
    profile_config.update(config[arguments.profile])

    response = requests.post(url, json=profile_config)
    if response.status_code == 400 and 'MFA missing' in response.text:
        profile_config['mfa_token_code'] = input('Enter MFA: ')
        response = requests.post(url, json=profile_config)

    if response.status_code != 200:
        print(response.text)


if __name__ == '__main__':
    main()
