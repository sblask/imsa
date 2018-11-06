import datetime
import unittest
import unittest.mock

import imsa

ONE_HOUR_AGO = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

ACCESS_KEY_SESSION = 'XXXXXXXXXXXXXXXXXXXX'
ACCESS_KEY_ROLE = 'YYYYYYYYYYYYYYYYYYYY'

SAMPLE_CONFIG = {
    'aws_access_key_id': 'XXXXXXXXXXXXXXXXXXXX',
    'aws_secret_access_key': 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
    'mfa_serial_number': 'arn:aws:iam::XXXXXXXXXXXX:mfa/UserName',
    'role_arn': 'arn:aws:iam::XXXXXXXXXXXX:role/RoleNameOne',
    'role_session_name': 'SomeSessionName',
}

SAMPLE_CREDENTIALS_SESSION = {
    'AccessKeyId': ACCESS_KEY_SESSION,
    'Expiration': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    'LastUpdated': datetime.datetime.utcnow(),
    'SecretAccessKey': 'YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY',
    'SessionToken': 'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ',
}

SAMPLE_CREDENTIALS_ROLE = dict(SAMPLE_CREDENTIALS_SESSION)
SAMPLE_CREDENTIALS_ROLE['AccessKeyId'] = ACCESS_KEY_ROLE

EXPIRED_CREDENTIALS_SESSION = dict(SAMPLE_CREDENTIALS_SESSION)
EXPIRED_CREDENTIALS_SESSION['Expiration'] = ONE_HOUR_AGO

EXPIRED_CREDENTIALS_ROLE = dict(EXPIRED_CREDENTIALS_SESSION)
EXPIRED_CREDENTIALS_ROLE['AccessKeyId'] = ACCESS_KEY_ROLE


class StateTests(unittest.TestCase):
    def setUp(self):
        self.state = imsa.State.get_instance()

    def tearDown(self):
        del imsa.State.instance

    def assert_access_key(self, access_key):
        credentials = self.state.get_credentials()
        assert credentials
        self.assertEqual(credentials['AccessKeyId'], access_key)

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_no_role(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS_SESSION
        get_role_mock.return_value = SAMPLE_CREDENTIALS_ROLE

        config_without_role = {}
        for key in imsa.CONFIG_KEYS_REQUIRING_SESSION_UPDATE:
            config_without_role[key] = SAMPLE_CONFIG[key]

        assert not self.state.requires_mfa(config_without_role)

        self.state.update_credentials(config_without_role)
        assert get_session_mock.called
        assert not get_role_mock.called

        self.assert_access_key(ACCESS_KEY_SESSION)

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_role_no_role(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS_SESSION
        get_role_mock.return_value = SAMPLE_CREDENTIALS_ROLE

        self.state.update_credentials(SAMPLE_CONFIG)
        assert get_session_mock.called
        assert get_role_mock.called

        self.assert_access_key(ACCESS_KEY_ROLE)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        config_without_role = {}
        for key in imsa.CONFIG_KEYS_REQUIRING_SESSION_UPDATE:
            config_without_role[key] = SAMPLE_CONFIG[key]

        self.state.update_credentials(config_without_role)
        assert not get_session_mock.called
        assert not get_role_mock.called

        self.assert_access_key(ACCESS_KEY_SESSION)

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_require_mfa(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS_SESSION
        get_role_mock.return_value = SAMPLE_CREDENTIALS_ROLE

        assert self.state.requires_mfa(SAMPLE_CONFIG)

        self.state.update_credentials(SAMPLE_CONFIG)
        assert get_session_mock.called
        assert get_role_mock.called

        assert not self.state.requires_mfa(SAMPLE_CONFIG)

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_no_update(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS_SESSION
        get_role_mock.return_value = SAMPLE_CREDENTIALS_ROLE

        self.state.update_credentials(SAMPLE_CONFIG)
        self.assert_access_key(ACCESS_KEY_ROLE)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        self.state.update_credentials(SAMPLE_CONFIG)
        assert not get_session_mock.called
        assert not get_role_mock.called

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_session_update(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS_SESSION
        get_role_mock.return_value = SAMPLE_CREDENTIALS_ROLE

        self.state.update_credentials(SAMPLE_CONFIG)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        for key in imsa.CONFIG_KEYS_REQUIRING_SESSION_UPDATE:
            config = dict(SAMPLE_CONFIG)
            config[key] = 'new_value'

            self.state.update_credentials(config)
            self.assert_access_key(ACCESS_KEY_ROLE)

            assert get_session_mock.called
            assert get_role_mock.called

            get_session_mock.reset_mock()
            get_role_mock.reset_mock()

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_role_update(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS_SESSION
        get_role_mock.return_value = SAMPLE_CREDENTIALS_ROLE

        self.state.update_credentials(SAMPLE_CONFIG)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        for key in imsa.CONFIG_KEYS_REQUIRING_ASSUME_ROLE:
            config = dict(SAMPLE_CONFIG)
            config[key] = 'new_value'

            self.state.update_credentials(config)
            self.assert_access_key(ACCESS_KEY_ROLE)

            assert not get_session_mock.called
            assert get_role_mock.called

            get_session_mock.reset_mock()
            get_role_mock.reset_mock()

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_role_expired(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS_SESSION
        get_role_mock.return_value = EXPIRED_CREDENTIALS_ROLE

        self.state.update_credentials(SAMPLE_CONFIG)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        self.state.update_credentials(SAMPLE_CONFIG)
        self.assert_access_key(ACCESS_KEY_ROLE)

        assert not get_session_mock.called
        assert get_role_mock.called

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_session_expired(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = EXPIRED_CREDENTIALS_SESSION
        get_role_mock.return_value = SAMPLE_CREDENTIALS_ROLE

        self.state.update_credentials(SAMPLE_CONFIG)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        self.state.update_credentials(SAMPLE_CONFIG)
        self.assert_access_key(ACCESS_KEY_ROLE)

        assert get_session_mock.called
        assert get_role_mock.called


if __name__ == '__main__':
    unittest.main()
