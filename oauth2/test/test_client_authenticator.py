from oauth2.test import unittest
from mock import Mock
from oauth2.client_authenticator import ClientAuthenticator
from oauth2.datatype import Client
from oauth2.error import OAuthInvalidNoRedirectError, ClientNotFoundError
from oauth2.store import ClientStore
from oauth2.web import Request


class ClientAuthenticatorTestCase(unittest.TestCase):
    def setUp(self):
        self.client = Client(identifier="abc", secret="xyz",
                             redirect_uris=["http://callback"])
        self.client_store_mock = Mock(spec=ClientStore)

        self.authenticator = ClientAuthenticator(
            client_store=self.client_store_mock)

    def test_by_identifier(self):
        redirect_uri = "http://callback"

        self.client_store_mock.fetch_by_client_id.return_value = self.client

        request_mock = Mock(spec=Request)
        request_mock.get_param.side_effect = [self.client.identifier,
                                              redirect_uri]

        client = self.authenticator.by_identifier(request=request_mock)

        self.client_store_mock.fetch_by_client_id.\
            assert_called_with(self.client.identifier)
        self.assertEqual(client.redirect_uri, redirect_uri)

    def test_by_identifier_client_id_not_set(self):
        request_mock = Mock(spec=Request)
        request_mock.get_param.return_value = None

        with self.assertRaises(OAuthInvalidNoRedirectError) as expected:
            self.authenticator.by_identifier(request=request_mock)

        self.assertEqual(expected.exception.error, "missing_client_id")

    def test_by_identifier_unknown_client(self):
        request_mock = Mock(spec=Request)
        request_mock.get_param.return_value = "def"

        self.client_store_mock.fetch_by_client_id.\
            side_effect = ClientNotFoundError

        with self.assertRaises(OAuthInvalidNoRedirectError) as expected:
            self.authenticator.by_identifier(request=request_mock)

        self.assertEqual(expected.exception.error, "unknown_client")

    def test_by_identifier_unknown_redirect_uri(self):
        unknown_redirect_uri = "http://unknown.com"

        request_mock = Mock(spec=Request)
        request_mock.get_param.side_effect = [self.client.identifier,
                                              unknown_redirect_uri]

        self.client_store_mock.fetch_by_client_id.return_value = self.client

        with self.assertRaises(OAuthInvalidNoRedirectError) as expected:
            self.authenticator.by_identifier(request=request_mock)

        self.assertEqual(expected.exception.error, "invalid_redirect_uri")

    def test_by_identifier_secret(self):
        client_id = "abc"
        client_secret = "xyz"

        request_mock = Mock(spec=Request)

        source_mock = Mock(return_value=(client_id, client_secret))

        self.client_store_mock.fetch_by_client_id.return_value = self.client

        self.authenticator.source = source_mock
        client = self.authenticator.by_identifier_secret(request=request_mock)
        self.client_store_mock.fetch_by_client_id.\
            assert_called_with(client_id)
