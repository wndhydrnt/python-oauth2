import unittest

from mock import patch
from oauth2.datatype import AccessToken

def mock_time():
    return 1000

class AccessTokenTestCase(unittest.TestCase):
    @patch("time.time", mock_time)
    def test_expires_in_expired(self):
        access_token = AccessToken(client_id="abc",
                                   grant_type="client_credentials", token="def",
                                   expires_at=999)

        self.assertEqual(access_token.expires_in, 0)

    @patch("time.time", mock_time)
    def test_expires_in_not_expired(self):
        access_token = AccessToken(client_id="abc",
                                   grant_type="client_credentials", token="def",
                                   expires_at=1100)

        self.assertEqual(access_token.expires_in, 100)
