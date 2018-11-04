import datetime
import unittest
import unittest.mock

import imsa

ONE_HOUR_AGO = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

SAMPLE_CONFIG = {
    'aws_access_key_id': 'XXXXXXXXXXXXXXXXXXXX',
    'aws_secret_access_key': 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
    'mfa_serial_number': 'arn:aws:iam::XXXXXXXXXXXX:mfa/UserName',
    'role_arn': 'arn:aws:iam::XXXXXXXXXXXX:role/RoleNameOne',
    'role_session_name': 'SomeSessionName',
}

SAMPLE_CREDENTIALS = {
    'AccessKeyId': 'XXXXXXXXXXXXXXXXXXXX',
    'Expiration': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    'LastUpdated': datetime.datetime.utcnow(),
    'SecretAccessKey': 'YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY',
    'SessionToken': 'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ',
}

EXPIRED_CREDENTIALS = dict(SAMPLE_CREDENTIALS)
EXPIRED_CREDENTIALS['Expiration'] = ONE_HOUR_AGO


class StateTests(unittest.TestCase):
    def setUp(self):
        self.state = imsa.State.get_instance()

    def tearDown(self):
        del imsa.State.instance

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_no_role(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS
        get_role_mock.return_value = SAMPLE_CREDENTIALS

        config_without_role = {}
        for key in imsa.CONFIG_KEYS_REQUIRING_SESSION_UPDATE:
            config_without_role[key] = SAMPLE_CONFIG[key]

        assert not self.state.requires_mfa(config_without_role)

        self.state.update_credentials(config_without_role)
        assert get_session_mock.called
        assert not get_role_mock.called

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_require_mfa(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS
        get_role_mock.return_value = SAMPLE_CREDENTIALS

        assert self.state.requires_mfa(SAMPLE_CONFIG)

        self.state.update_credentials(SAMPLE_CONFIG)
        assert get_session_mock.called
        assert get_role_mock.called

        assert not self.state.requires_mfa(SAMPLE_CONFIG)

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_no_update(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS
        get_role_mock.return_value = SAMPLE_CREDENTIALS

        self.state.update_credentials(SAMPLE_CONFIG)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        self.state.update_credentials(SAMPLE_CONFIG)
        assert not get_session_mock.called
        assert not get_role_mock.called

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_session_update(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS
        get_role_mock.return_value = SAMPLE_CREDENTIALS

        self.state.update_credentials(SAMPLE_CONFIG)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        for key in imsa.CONFIG_KEYS_REQUIRING_SESSION_UPDATE:
            config = dict(SAMPLE_CONFIG)
            config[key] = 'new_value'

            self.state.update_credentials(config)
            assert get_session_mock.called
            assert get_role_mock.called

            get_session_mock.reset_mock()
            get_role_mock.reset_mock()

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_role_update(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS
        get_role_mock.return_value = SAMPLE_CREDENTIALS

        self.state.update_credentials(SAMPLE_CONFIG)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        for key in imsa.CONFIG_KEYS_REQUIRING_ASSUME_ROLE:
            config = dict(SAMPLE_CONFIG)
            config[key] = 'new_value'

            self.state.update_credentials(config)
            assert not get_session_mock.called
            assert get_role_mock.called

            get_session_mock.reset_mock()
            get_role_mock.reset_mock()

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_role_expired(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = SAMPLE_CREDENTIALS
        get_role_mock.return_value = EXPIRED_CREDENTIALS

        self.state.update_credentials(SAMPLE_CONFIG)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        self.state.update_credentials(SAMPLE_CONFIG)
        assert not get_session_mock.called
        assert get_role_mock.called

    @unittest.mock.patch('imsa.get_new_role_credentials')
    @unittest.mock.patch('imsa.get_new_session_credentials')
    def test_session_expired(self, get_session_mock, get_role_mock):
        get_session_mock.return_value = EXPIRED_CREDENTIALS
        get_role_mock.return_value = SAMPLE_CREDENTIALS

        self.state.update_credentials(SAMPLE_CONFIG)

        get_session_mock.reset_mock()
        get_role_mock.reset_mock()

        self.state.update_credentials(SAMPLE_CONFIG)
        assert get_session_mock.called
        assert get_role_mock.called


if __name__ == '__main__':
    unittest.main()
