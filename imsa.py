#!/usr/bin/env python
import argparse
import datetime
import functools
import inspect
import json
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
import requests.exceptions
import yaml

logger = logging.getLogger(__name__)


LOG_FORMAT = '%(asctime)s - %(levelname)7s - %(name)s - %(message)s'
SERVER_LOG_MAX_BYTES = 5 * 1024 * 1024

CONFIG_PATH = os.path.expanduser('~/.imsa')
CONFIG_KEYS_REQUIRING_SESSION_UPDATE = (
    'aws_access_key_id',
    'aws_secret_access_key',
    'mfa_serial_number',
)
CONFIG_KEYS_REQUIRING_ASSUME_ROLE = (
    'role_arn',
    'role_session_name',
)


IP_ADDRESS = '169.254.169.254'
INVALID_CREDENTIAL_PATH = '/latest/meta-data/iam/security-credentials'
CREDENTIAL_PATH = INVALID_CREDENTIAL_PATH + '/'
DUMMY_ROLE = 'imsa'

CONTROL_PATH = '/__imsa/%s/'
CONTROL_PATH_ASSUME = CONTROL_PATH % 'assume'
CONTROL_PATH_STOP = CONTROL_PATH % 'stop'
CONTROL_PATH_STATUS = CONTROL_PATH % 'status'
CONTROL_PATH_TEMPORARY_CREDENTIALS = CONTROL_PATH % 'temporary_credentials'

MINIMUM_MINUTES_IN_SESSION = 5
REFRESH_CHECK_INTERVAL = 3 * 60

HELP_STRINGS = ['-h', '--h', '--he', '--hel', '--help']

EXPORT_TEMPLATE = """
export AWS_ACCESS_KEY_ID={AccessKeyId}
export AWS_SECRET_ACCESS_KEY={SecretAccessKey}
export AWS_SESSION_TOKEN={SessionToken}
export IMSA_PROFILE={profile}
export IMSA_PROFILE_EXPIRATION={Expiration}
"""


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
    __add_status_parser(subparsers)
    __add_export_parser(subparsers)

    argcomplete.autocomplete(parser)
    return parser.parse_args()


def __add_start_parser(parser):
    start_parser = parser.add_parser(
        'start',
        help=(
            'Start the instance metadata service'
        ),
    )
    start_parser.set_defaults(function=server_start)
    __add_common_arguments(start_parser)

    start_parser.add_argument(
        '--log-file',
        help='Log to this file instead of the command line',
    )


def __add_stop_parser(parser):
    stop_parser = parser.add_parser(
        'stop',
        help=(
            'Stop the instance metadata service'
        ),
    )
    stop_parser.set_defaults(function=client_stop)
    __add_common_arguments(stop_parser)


def __add_assume_parser(parser):
    assume_parser = parser.add_parser(
        'assume',
        help=(
            'Make credentials for the given profile available through the'
            ' instance metadata service'
        ),
    )
    __add_common_arguments(assume_parser)
    __add_profile_argument(assume_parser, 'assume', client_assume)


def __add_profile_argument(subcommand_parser, command_name, default_function):
    profile_argument = subcommand_parser.add_argument('profile')

    is_help_call = any([string in sys.argv for string in HELP_STRINGS])
    # config should only be loaded for commands that need it, not the others
    # this IF is required as parse_known_args would break argcomplete and help
    if len(sys.argv) > 1 and sys.argv[1] == command_name or is_help_call:
        config = __load_config()
        choices = sorted(config.keys())

        profile_argument.choices = choices

        function = functools.partial(default_function, config)
        subcommand_parser.set_defaults(function=function)

    # need to add this completer as choices is not available during completion
    profile_argument.completer = __profile_completer


def __add_export_parser(parser):
    export_parser = parser.add_parser(
        'export',
        help=(
            'Outputs environment variables with credentials for the given'
            ' profile reusing existing credentials if possible, but without'
            ' updating the credentials available through the instance metadata'
            ' service'
        ),
    )

    __add_common_arguments(export_parser)
    __add_profile_argument(export_parser, 'export', client_export)


def __add_status_parser(parser):
    status_parser = parser.add_parser(
        'status',
        help=(
            'Show information about current credentials'
        ),
    )
    status_parser.set_defaults(function=client_status)
    __add_common_arguments(status_parser)


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
            maxBytes=SERVER_LOG_MAX_BYTES,
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


def have_credentials_expired(credentials):
    if not credentials:
        return False
    now = datetime.datetime.utcnow()
    soon = now + datetime.timedelta(minutes=MINIMUM_MINUTES_IN_SESSION)
    expiration = credentials['Expiration'].replace(tzinfo=None)
    return expiration < soon


def config_contains_role_config(new_config):
    for key in CONFIG_KEYS_REQUIRING_ASSUME_ROLE:
        if key not in new_config:
            logger.info('No %s in given config', key)
            return False
    return True


def get_new_session_credentials(config):
    try:
        client = boto3.client(
            'sts',
            aws_access_key_id=config['aws_access_key_id'],
            aws_secret_access_key=config['aws_secret_access_key'],
        )
        if 'mfa_serial_number' in config and 'mfa_token_code' in config:
            response = client.get_session_token(
                SerialNumber=config['mfa_serial_number'],
                TokenCode=config['mfa_token_code'],
            )
        else:
            response = client.get_session_token()
        credentials = response['Credentials']
        credentials['LastUpdated'] = datetime.datetime.utcnow()
        return credentials
    except Exception:
        logging.exception('Could not get new session credentials')
        raise


def get_new_role_credentials(session_credentials, config):
    try:
        client = boto3.client(
            'sts',
            aws_access_key_id=session_credentials['AccessKeyId'],
            aws_secret_access_key=session_credentials['SecretAccessKey'],
            aws_session_token=session_credentials['SessionToken'],
        )
        response = client.assume_role(
            RoleArn=config['role_arn'],
            RoleSessionName=config['role_session_name'],
        )
        credentials = response['Credentials']
        credentials['LastUpdated'] = datetime.datetime.utcnow()
        return credentials
    except Exception:
        logging.exception('Could not get new role credentials')
        raise


class State():

    def __init__(self):
        self.server = None
        self.__config = {}
        self.__session_credentials = {}
        self.__role_credentials = {}

        self.schedule_refresh()

    @classmethod
    def get_instance(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = State()
        return cls.instance

    def schedule_refresh(self):
        def maybe_refresh_credentials():
            logger.info('Maybe refresh credentials')
            self.schedule_refresh()
            logger.info('Scheduled')
            self.update_role_credentials_if_expired()

        timer = threading.Timer(
            REFRESH_CHECK_INTERVAL,
            maybe_refresh_credentials,
        )
        timer.daemon = True
        timer.start()

    def get_status(self):
        return {'assumed_profile': self.__config.get('profile_name', None)}

    def requires_mfa(self, new_config):
        if 'mfa_serial_number' not in new_config:
            return False
        return self.__new_session_credentials_required(new_config)

    def get_credentials(self):
        return self.__role_credentials or self.__session_credentials

    def update_credentials(self, new_config):
        new_session_credentials, new_role_credentials = \
            self.__new_credentials(new_config)

        if new_session_credentials is not None:
            self.__session_credentials = new_session_credentials

        if new_role_credentials is not None:
            self.__role_credentials = new_role_credentials

        self.__config = new_config

    def temporary_credentials(self, config):
        new_session_credentials, new_role_credentials = \
            self.__new_credentials(config)

        return \
            new_role_credentials or \
            new_session_credentials or \
            self.get_credentials()

    def __new_credentials(self, new_config):
        new_session_credentials = None
        if self.__new_session_credentials_required(new_config):
            logger.info('Update session credentials')
            new_session_credentials = get_new_session_credentials(new_config)

        new_role_credentials = self.___new_role_credentials(
            new_config,
            new_session_credentials,
        )
        return new_session_credentials, new_role_credentials

    def ___new_role_credentials(self, new_config, new_session_credentials):
        if not config_contains_role_config(new_config):
            return {}

        if not self.__role_credentials:
            logger.info('Config requires role credentials')
            return get_new_role_credentials(
                new_session_credentials or self.__session_credentials,
                new_config,
            )
        if new_session_credentials:
            logger.info('Session updated, update role credentials')
            return get_new_role_credentials(
                new_session_credentials,
                new_config,
            )
        if have_credentials_expired(self.__role_credentials):
            logger.info('Role credentials have expired')
            return get_new_role_credentials(
                self.__session_credentials,
                new_config,
            )
        if self.__has_role_config_changed(new_config):
            logger.info('Configured role has changed')
            return get_new_role_credentials(
                self.__session_credentials,
                new_config,
            )

        logger.info('Role is configured but no update is necessary')
        return None

    def update_role_credentials_if_expired(self):
        if have_credentials_expired(self.__role_credentials):
            logger.info('Update role credentials')
            self.__role_credentials = get_new_role_credentials(
                self.__session_credentials,
                self.__config,
            )

    def __new_session_credentials_required(self, new_config):
        if not self.__session_credentials:
            return True
        if have_credentials_expired(self.__session_credentials):
            return True
        for key in CONFIG_KEYS_REQUIRING_SESSION_UPDATE:
            if new_config.get(key, None) != self.__config.get(key, None):
                return True
        return False

    def __has_role_config_changed(self, new_config):
        for key in CONFIG_KEYS_REQUIRING_ASSUME_ROLE:
            if new_config.get(key, None) != self.__config.get(key, None):
                return True
        return False


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
        credentials = state.get_credentials()
        if not credentials:
            return pyramid.httpexceptions.HTTPNotFound('No role assumed')
        return pyramid.response.Response(json=__response_dict(credentials))
    except botocore.exceptions.ClientError as exception:
        error_message = exception.response['Error']['Message']
        logger.warning(error_message)
        return pyramid.httpexceptions.HTTPNotFound(error_message)


def __response_dict(credentials):
    return {
        'AccessKeyId': credentials['AccessKeyId'],
        'Code': 'Success',
        'Expiration': _format_datetime(credentials['Expiration']),
        'LastUpdated': _format_datetime(credentials['LastUpdated']),
        'SecretAccessKey': credentials['SecretAccessKey'],
        'Token': credentials['SessionToken'],
        'Type': 'AWS-HMAC',
    }


def _format_datetime(datetime_object):
    cleaned = datetime_object.replace(microsecond=0, tzinfo=None)
    return cleaned.isoformat('T') + 'Z'


@__register_route(CONTROL_PATH_STOP)
def server_stop(_request):
    logger.info('Stop server')
    server = State.get_instance().server
    threading.Thread(target=server.shutdown).start()
    return pyramid.response.Response()


@__register_route(CONTROL_PATH_ASSUME)
def server_assume(request):
    return __handle_boto_exceptions(request, __server_assume)


def __handle_boto_exceptions(request, function):
    try:
        state = State.get_instance()
        config = request.json

        if state.requires_mfa(config) and 'mfa_token_code' not in config:
            return pyramid.httpexceptions.HTTPBadRequest('MFA missing')

        return function(request)
    except botocore.exceptions.ParamValidationError as exception:
        error_message = str(exception).replace('\n', ' ')
        logger.warning(error_message)
        return pyramid.response.Response(
            error_message,
            status=pyramid.httpexceptions.HTTPBadRequest.code,
        )
    except botocore.exceptions.ClientError as exception:
        error_message = exception.response['Error']['Message']
        logger.warning(error_message)
        return pyramid.response.Response(
            error_message,
            status=pyramid.httpexceptions.HTTPBadRequest.code,
        )


def __server_assume(request):
    config = request.json
    State.get_instance().update_credentials(config)
    return pyramid.response.Response()


@__register_route(CONTROL_PATH_STATUS)
def server_status(_request):
    status = State.get_instance().get_status()
    return pyramid.response.Response(json=status)


@__register_route(CONTROL_PATH_TEMPORARY_CREDENTIALS)
def server_temporary_credentials(request):
    return __handle_boto_exceptions(request, __server_temporary_credentials)


class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):  # pylint: disable=method-hidden
        if isinstance(o, datetime.datetime):
            return _format_datetime(o)

        return super().default(o)


def __server_temporary_credentials(request):
    config = request.json
    credentials = State.get_instance().temporary_credentials(config)
    return pyramid.response.Response(
        json.dumps(credentials, cls=DateTimeEncoder),
        charset='UTF-8',
        content_type='application/json',
    )


@pyramid.view.exception_view_config(Exception)
def server_exception(_exc, _request):
    logger.exception('An exception caused an internal server error')
    return pyramid.response.Response(
        'Internal Server Error - Check log for details',
        status=pyramid.httpexceptions.HTTPInternalServerError.code,
    )


def __handle_server_unreachable(function):
    def wrapper(*args, **kwargs):
        try:
            function(*args, **kwargs)
        except requests.exceptions.ConnectionError:
            print('IMSA server could not be reached')
    return wrapper


@__handle_server_unreachable
def client_stop(arguments):
    address = ':'.join([IP_ADDRESS, str(arguments.port)])
    requests.post(
        'http://' + address + CONTROL_PATH_STOP,
    )


@__handle_server_unreachable
def client_assume(config, arguments):
    __make_profile_request(config, arguments, CONTROL_PATH_ASSUME)


def __make_profile_request(config, arguments, control_path):
    address = ':'.join([IP_ADDRESS, str(arguments.port)])
    url = 'http://' + address + control_path

    profile_config = _get_profile_config(config, arguments.profile)
    profile_config['profile_name'] = arguments.profile

    response = requests.post(url, json=profile_config)
    if response.status_code == 400 and 'MFA missing' in response.text:
        profile_config['mfa_token_code'] = input('Enter MFA: ')
        response = requests.post(url, json=profile_config)

    if response.status_code != 200:
        print(response.text)
        return None

    return response


def _get_profile_config(config, profile_name):
    profile_config = config[profile_name]
    if 'extends' in profile_config:
        extended_config = _get_profile_config(
            config,
            profile_config['extends'],
        )
        extended_config.update(profile_config)
        del extended_config['extends']
        return extended_config
    else:
        return profile_config


@__handle_server_unreachable
def client_status(arguments):
    address = ':'.join([IP_ADDRESS, str(arguments.port)])
    url = 'http://' + address + CONTROL_PATH_STATUS

    response = requests.get(url)
    print(response.json())


@__handle_server_unreachable
def client_export(config, arguments):
    response = __make_profile_request(
        config,
        arguments,
        CONTROL_PATH_TEMPORARY_CREDENTIALS,
    )

    if not response:
        return

    credentials = response.json()
    export_string = EXPORT_TEMPLATE.format(
        profile=arguments.profile,
        **credentials
    )

    print(export_string)


if __name__ == '__main__':
    main()
