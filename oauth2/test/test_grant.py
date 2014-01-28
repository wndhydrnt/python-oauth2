from mock import Mock, call, patch
import json
from oauth2.test import unittest
from oauth2.web import Request, Response, SiteAdapter
from oauth2.grant import ImplicitGrantHandler, AuthorizationCodeAuthHandler, \
    AuthRequestMixin, AuthorizationCodeTokenHandler, ImplicitGrant, \
    AuthorizationCodeGrant, ResourceOwnerGrantHandler, ResourceOwnerGrant, \
    Scope, RefreshToken, RefreshTokenHandler, ScopeGrant, \
    ClientCredentialsGrant, ClientCredentialsHandler, AuthorizeMixin
from oauth2.store import ClientStore, AuthCodeStore, AccessTokenStore
from oauth2.error import OAuthInvalidError, OAuthUserError, OAuthClientError, \
    ClientNotFoundError, UserNotAuthenticated, AccessTokenNotFound
from oauth2 import Provider
from oauth2.datatype import Client, AuthorizationCode, AccessToken
from oauth2.tokengenerator import TokenGenerator

def mock_time():
    return 1000

class AuthorizationCodeGrantTestCase(unittest.TestCase):
    def test_create_auth_handler(self):
        """
        AuthorizationCodeGrant() should return a new instance of AuthorizationCodeAuthHandler on request
        """
        default_scope = "default_scope"
        scopes = ["first", "second"]
        path = "/auth"

        request_mock = Mock(spec=Request)
        request_mock.path = path
        request_mock.get_param.return_value = "code"

        scope_mock = Mock(Scope)

        server_mock = Mock()
        server_mock.authorize_path = path
        server_mock.auth_code_store = Mock()
        server_mock.client_store = Mock()
        server_mock.site_adapter = Mock()
        server_mock.token_generator = Mock()

        factory = AuthorizationCodeGrant(default_scope=default_scope,
                                         scopes=scopes,
                                         scope_class=scope_mock)
        result_class = factory(request_mock, server_mock)

        request_mock.get_param.assert_called_with("response_type")
        scope_mock.assert_called_with(default=default_scope, available=scopes)
        self.assertTrue(isinstance(result_class, AuthorizationCodeAuthHandler))

    def test_create_token_handler(self):
        path = "/token"

        request_mock = Mock(spec=Request)
        request_mock.path = path
        request_mock.post_param.return_value = "authorization_code"

        server_mock = Mock()
        server_mock.authorize_path = "/auth"
        server_mock.token_path = path
        server_mock.access_token_store = Mock(spec=AccessTokenStore)
        server_mock.auth_code_store = Mock()
        server_mock.client_store = Mock()
        server_mock.token_generator = Mock()

        factory = AuthorizationCodeGrant()
        result_class = factory(request_mock, server_mock)

        request_mock.post_param.assert_called_with("grant_type")
        self.assertTrue(isinstance(result_class,
                                   AuthorizationCodeTokenHandler))

    def test_create_no_match(self):
        request_mock = Mock(spec=Request)
        request_mock.get_param.return_value = "no-code"
        request_mock.post_param.return_value = "no-authorization_code"

        factory = AuthorizationCodeGrant()
        result_class = factory(request_mock, Mock())

        request_mock.get_param.assert_called_with("response_type")
        request_mock.post_param.assert_called_with("grant_type")
        self.assertEqual(result_class, None)

class AuthRequestMixinTestCase(unittest.TestCase):
    def test_read_validate_params_all_valid(self):
        """
        AuthRequestMixin.read_validate_params should parse all params correctly if they are valid
        """
        client_id = "cid"
        redirect_uri = "http://somewhere"
        state = "state"

        client_mock = Mock(Client)
        client_mock.redirect_uris = [redirect_uri]

        request_mock = Mock(spec=Request)
        request_mock.get_param.side_effect = [client_id, None, state]

        scope_handler_mock = Mock(Scope)

        clientStoreMock = Mock(spec=ClientStore)
        clientStoreMock.fetch_by_client_id.return_value = client_mock

        handler = AuthRequestMixin(client_store=clientStoreMock,
                                   scope_handler=scope_handler_mock,
                                   token_generator=Mock())

        result = handler.read_validate_params(request_mock)

        request_mock.get_param.assert_has_calls([call("client_id"),
                                                call("redirect_uri"),
                                                call("state")])
        scope_handler_mock.parse.assert_called_with(request_mock, "query")
        clientStoreMock.fetch_by_client_id.assert_called_with(client_id)
        self.assertEqual(handler.client_id, client_id)
        self.assertEqual(handler.redirect_uri, redirect_uri)
        self.assertEqual(handler.state, state)
        self.assertTrue(result)

    def test_read_validate_params_no_client_id(self):
        """
        AuthRequestMixin.read_validate_params should raise an OAuthInvalidError if no client_id in request
        """
        request_mock = Mock(spec=Request)
        request_mock.get_param.return_value = None

        handler = AuthRequestMixin(client_store=Mock(), scope_handler=Mock(),
                                   token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        e = expected.exception

        request_mock.get_param.assert_called_with("client_id")
        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "Missing client_id parameter")

    def test_read_validate_params_unknown_client_id(self):
        """
        AuthRequestMixin.read_validate_params should raise an OAuthInvalidError if no client with given client_id exists
        """
        client_id = "abc"

        request_mock = Mock(spec=Request)
        request_mock.get_param.return_value = client_id

        clientStoreMock = Mock(spec=ClientStore)
        clientStoreMock.fetch_by_client_id.side_effect = ClientNotFoundError

        handler = AuthRequestMixin(client_store=clientStoreMock,
                                   scope_handler=Mock(),
                                   token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        e = expected.exception

        request_mock.get_param.assert_called_with("client_id")
        clientStoreMock.fetch_by_client_id.assert_called_with(client_id)
        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "No client registered")

    def test_read_validate_params_invalid_redirect_uri(self):
        """
        AuthRequestMixin.read_validate_params should raise an OAuthInvalidError if redirect_uri is invalid
        """
        client_id = "abc"
        redirect_uri = "http://endpoint-one"

        client_mock = Mock(Client)
        client_mock.has_redirect_uri.return_value = False

        request_mock = Mock(spec=Request)
        request_mock.get_param.side_effect = [client_id, redirect_uri]

        clientStoreMock = Mock(spec=ClientStore)
        clientStoreMock.fetch_by_client_id.return_value = client_mock

        handler = AuthRequestMixin(client_store=clientStoreMock,
                                   scope_handler=Mock(),
                                   token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        e = expected.exception

        request_mock.get_param.assert_has_calls([call("client_id"),
                                                call("redirect_uri")])
        clientStoreMock.fetch_by_client_id.assert_called_with(client_id)
        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "redirect_uri is not registered for this client")

    def test_read_validate_params_default_redirect_uri(self):
        """
        AuthRequestMixin.read_validate_params should use the correct redirect uri when the client has registered more than one
        """
        client_id = "cid"
        redirect_uri = "http://somewhere"
        state = "state"

        client_mock = Mock(Client)
        client_mock.redirect_uris = ["http://somewhere-else", redirect_uri]

        request_mock = Mock(spec=Request)
        request_mock.get_param.side_effect = [client_id, redirect_uri, state]

        scope_handler_mock = Mock(Scope)

        clientStoreMock = Mock(spec=ClientStore)
        clientStoreMock.fetch_by_client_id.return_value = client_mock

        handler = AuthRequestMixin(client_store=clientStoreMock,
                                   scope_handler=scope_handler_mock,
                                   token_generator=Mock())

        result = handler.read_validate_params(request_mock)

        request_mock.get_param.assert_has_calls([call("client_id"),
                                                call("redirect_uri"),
                                                call("state")])
        scope_handler_mock.parse.assert_called_with(request_mock, "query")
        clientStoreMock.fetch_by_client_id.assert_called_with(client_id)
        self.assertEqual(handler.client_id, client_id)
        self.assertEqual(handler.redirect_uri, redirect_uri)
        self.assertEqual(handler.state, state)
        self.assertTrue(result)

class AuthorizeMixinTestCase(unittest.TestCase):
    def test_authorize_user_denied_access(self):
        """
        AuthorizeMixin.authorize should raise an OAuthUserError if the user did not authorize the request
        """
        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.user_has_denied_access.return_value = True

        auth_mixin = AuthorizeMixin(site_adapter=site_adapter_mock)
        with self.assertRaises(OAuthUserError):
            auth_mixin.authorize(Mock(spec=Request), Mock(spec=Response),
                                 environ={}, scopes=[])

    def test_authorize_dict_return(self):
        """
        AuthorizeMixin.authorize should return a tuple even if the SiteAdapter returns a dict
        """
        test_data = {"test": "data"}

        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.user_has_denied_access.return_value = False
        site_adapter_mock.authenticate.return_value = test_data

        auth_mixin = AuthorizeMixin(site_adapter=site_adapter_mock)
        result = auth_mixin.authorize(Mock(spec=Request), Mock(spec=Response),
                                      environ={}, scopes=[])

        self.assertTrue(isinstance(result, tuple))
        self.assertDictEqual(result[0], test_data)
        self.assertIsNone(result[1])

    def test_authorize_tuple_return(self):
        """
        AuthorizeMixin.authorize should return the tuple returned by the SiteAdapter
        """
        test_data = ({"test": "data"}, 123)

        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.user_has_denied_access.return_value = False
        site_adapter_mock.authenticate.return_value = test_data

        auth_mixin = AuthorizeMixin(site_adapter=site_adapter_mock)
        result = auth_mixin.authorize(Mock(spec=Request), Mock(spec=Response),
                                      environ={}, scopes=[])

        self.assertTrue(isinstance(result, tuple))
        self.assertDictEqual(result[0], test_data[0])
        self.assertEqual(result[1], test_data[1])

    def test_authorize_user_not_authenticated(self):
        response_mock = Mock(spec=Response)

        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.user_has_denied_access.return_value = False
        site_adapter_mock.authenticate.side_effect = UserNotAuthenticated
        site_adapter_mock.render_auth_page.return_value = response_mock

        auth_mixin = AuthorizeMixin(site_adapter=site_adapter_mock)
        result = auth_mixin.authorize(Mock(spec=Request), response_mock,
                                      environ={}, scopes=[])

        self.assertEqual(result, response_mock)

class AuthorizationCodeAuthHandlerTestCase(unittest.TestCase):
    def test_process(self):
        client_id = "foobar"
        code = "abcd"
        environ = {"session": "data"}
        scopes = ["scope"]
        state = "mystate"
        redirect_uri = "https://callback"
        user_data = {"user_id": 789}

        location_uri = "%s?code=%s&state=%s" % (redirect_uri, code, state)

        auth_code_store_mock = Mock(spec=AuthCodeStore)

        response_mock = Mock(spec=Response)

        request_mock = Mock(spec=Request)

        scope_handler_mock = Mock(Scope)
        scope_handler_mock.scopes = scopes
        scope_handler_mock.send_back = False

        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.return_value = user_data
        site_adapter_mock.user_has_denied_access.return_value = False

        token_generator_mock = Mock(spec=["generate"])
        token_generator_mock.generate.return_value = code

        handler = AuthorizationCodeAuthHandler(
            auth_token_store=auth_code_store_mock,
            client_store=Mock(), scope_handler=scope_handler_mock,
            site_adapter=site_adapter_mock,
            token_generator=token_generator_mock
        )

        handler.client_id = client_id
        handler.state = state
        handler.redirect_uri = redirect_uri
        response = handler.process(request_mock, response_mock, environ)

        token_generator_mock.generate.assert_called_with()
        site_adapter_mock.authenticate.assert_called_with(request_mock,
                                                          environ, scopes)
        self.assertTrue(auth_code_store_mock.save_code.called)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.body, "")
        response_mock.add_header.assert_called_with("Location", location_uri)

    def test_process_redirect_with_scopes(self):
        client_id = "foobar"
        code = "abcd"
        environ = {"session": "data"}
        scopes = ["scope_read", "scope_write"]
        scopes_uri = "%20".join(scopes)
        state = "mystate"
        redirect_uri = "https://callback"
        user_data = {"user_id": 789}

        location_uri = "%s?code=%s&state=%s&scope=%s" % (redirect_uri, code, state, scopes_uri)

        response_mock = Mock(spec=Response)

        scope_handler_mock = Mock(Scope)
        scope_handler_mock.scopes = scopes
        scope_handler_mock.send_back = True

        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.return_value = user_data

        token_generator_mock = Mock(spec=["generate"])
        token_generator_mock.generate.return_value = code

        handler = AuthorizationCodeAuthHandler(
            auth_token_store=Mock(spec=AuthCodeStore),
            client_store=Mock(), scope_handler=scope_handler_mock,
            site_adapter=site_adapter_mock,
            token_generator=token_generator_mock
        )

        handler.client_id = client_id
        handler.state = state
        handler.redirect_uri = redirect_uri
        response = handler.process(Mock(spec=Request), response_mock, environ)

        token_generator_mock.generate.assert_called_with()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.body, "")
        response_mock.add_header.assert_called_with("Location", location_uri)

    def test_process_not_confirmed(self):
        """
        AuthorizationCodeAuthHandler.process should call SiteAdapter.render_auth_page if the user could not be authenticated
        """
        environ = {"session": "data"}
        response_mock = Mock(spec=Response)
        scopes = ["scopes"]

        request_mock = Mock(spec=Request)

        scope_handler_mock = Mock(Scope)
        scope_handler_mock.scopes = scopes

        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.side_effect = UserNotAuthenticated
        site_adapter_mock.render_auth_page.return_value = response_mock

        handler = AuthorizationCodeAuthHandler(
            auth_token_store=Mock(), client_store=Mock(),
            scope_handler=scope_handler_mock, site_adapter=site_adapter_mock,
            token_generator=Mock()
        )
        response = handler.process(request_mock, response_mock, environ)

        site_adapter_mock.render_auth_page.assert_called_with(request_mock,
                                                              response_mock,
                                                              environ,
                                                              scopes)
        self.assertEqual(response, response_mock)

    def test_redirect_oauth_error(self):
        error_identifier = "eid"
        redirect_uri = "https://callback"

        expected_redirect = "%s?error=%s" % (redirect_uri, error_identifier)

        error_mock = Mock(spec=OAuthUserError)
        error_mock.error = error_identifier

        response_mock = Mock(spec=Response)

        handler = AuthorizationCodeAuthHandler(
            auth_token_store=Mock(), client_store=Mock(), scope_handler=Mock(),
            site_adapter=Mock(), token_generator=Mock()
        )
        handler.redirect_uri = redirect_uri
        result = handler.redirect_oauth_error(error_mock, response_mock)

        response_mock.add_header.assert_called_with("Location",
                                                    expected_redirect)
        response_mock.status_code = 302
        response_mock.body = ""
        self.assertEqual(result, response_mock)


class AuthorizationCodeTokenHandlerTestCase(unittest.TestCase):
    def test_read_validate_params(self):
        client_id = "abc"
        client_secret = "t%gH"
        code = "defg"
        data = {"additional": "data"}
        redirect_uri = "http://callback"
        scopes = ["scope"]
        user_id = 123

        auth_code = Mock(AuthorizationCode)
        auth_code.code = code
        auth_code.data = data
        auth_code.is_expired.return_value = False
        auth_code.redirect_uri = redirect_uri
        auth_code.scopes = scopes
        auth_code.user_id = user_id

        auth_code_store_mock = Mock(spec=AuthCodeStore)
        auth_code_store_mock.fetch_by_code.return_value = auth_code

        client_mock = Mock(Client)
        client_mock.secret = client_secret
        client_mock.redirect_uris = [redirect_uri]

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret, code,
                                               redirect_uri]

        handler = AuthorizationCodeTokenHandler(
            access_token_store=Mock(spec=AccessTokenStore),
            auth_token_store=auth_code_store_mock,
            client_store=client_store_mock,
            token_generator=Mock())

        result = handler.read_validate_params(request_mock)

        request_mock.post_param.assert_has_calls([call("client_id"),
                                                  call("client_secret"),
                                                  call("code"),
                                                  call("redirect_uri")])
        auth_code_store_mock.fetch_by_code.assert_called_with(code)
        self.assertEqual(handler.client_id, client_id)
        self.assertEqual(handler.client_secret, client_secret)
        self.assertEqual(handler.code, code)
        self.assertEqual(handler.data, data)
        self.assertEqual(handler.redirect_uri, redirect_uri)
        self.assertEqual(handler.scopes, scopes)
        self.assertEqual(handler.user_id, user_id)
        self.assertTrue(result)

    def test_read_validate_params_missing_code(self):
        client_id = "abc"
        client_secret = "t%gH"
        code = None
        redirect_uri = "http://callback"

        client_mock = Mock(Client)
        client_mock.secret = client_secret

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret, code,
                                               redirect_uri]

        handler = AuthorizationCodeTokenHandler(
            access_token_store=Mock(spec=AccessTokenStore),
            auth_token_store=Mock(spec=AuthCodeStore),
            client_store=client_store_mock,
            token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation,
                         "Missing required parameter in request")

    def test_read_validate_params_unknown_code(self):
        client_id = "abc"
        client_secret = "t%gH"
        code_expected = "defg"
        code_actual = "xyz"
        redirect_uri = "http://callback"

        auth_code_mock = Mock(AuthorizationCode)
        auth_code_mock.code = code_expected

        auth_code_store_mock = Mock(spec=AuthCodeStore)
        auth_code_store_mock.fetch_by_code.return_value = auth_code_mock

        client_mock = Mock(Client)
        client_mock.secret = client_secret
        client_mock.redirect_uris = [redirect_uri]

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               code_actual, redirect_uri]

        handler = AuthorizationCodeTokenHandler(
            access_token_store=Mock(spec=AccessTokenStore),
            auth_token_store=auth_code_store_mock,
            client_store=client_store_mock,
            token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        self.assertEqual(error.error, "invalid_grant")
        self.assertEqual(error.explanation, "Invalid code parameter in request")

    def test_read_validate_params_unknown_client(self):
        client_id = "abc"
        client_secret = "t%gH"
        code = "xyz"
        redirect_uri = "http://callback"

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.side_effect = ClientNotFoundError

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret, code,
                                               redirect_uri]

        handler = AuthorizationCodeTokenHandler(
            access_token_store=Mock(spec=AccessTokenStore),
            auth_token_store=Mock(spec=AuthCodeStore),
            client_store=client_store_mock,
            token_generator=Mock())

        with self.assertRaises(OAuthClientError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        self.assertEqual(error.error, "invalid_client")
        self.assertEqual(error.explanation, "Unknown client")

    def test_read_validate_params_wrong_client_secret(self):
        client_id = "abc"
        client_secret_actual = "invalid"
        client_secret_expected = "t%gH"
        code = "xyz"
        redirect_uri = "http://callback"

        client_mock = Mock(Client)
        client_mock.secret = client_secret_expected
        client_mock.redirect_uris = [redirect_uri]

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret_actual,
                                               code, redirect_uri]

        handler = AuthorizationCodeTokenHandler(
            access_token_store=Mock(spec=AccessTokenStore),
            auth_token_store=Mock(spec=AuthCodeStore),
            client_store=client_store_mock,
            token_generator=Mock())

        with self.assertRaises(OAuthClientError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        self.assertEqual(error.error, "invalid_client")
        self.assertEqual(error.explanation, "Invalid client_secret")

    def test_read_validate_params_wrong_redirect_uri_in_client_data(self):
        client_id = "abc"
        client_secret = "t%gH"
        code = "xyz"
        redirect_uri = "http://invalid-callback"

        client_mock = Mock(Client)
        client_mock.secret = client_secret
        client_mock.has_redirect_uri.return_value = False

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               code, redirect_uri]

        handler = AuthorizationCodeTokenHandler(
            access_token_store=Mock(spec=AccessTokenStore),
            auth_token_store=Mock(spec=AuthCodeStore),
            client_store=client_store_mock,
            token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation, "Invalid redirect_uri parameter")

    def test_read_validate_params_no_auth_code_found(self):
        client_id = "abc"
        client_secret = "t%gH"
        code = "xyz"
        redirect_uri = "http://callback"

        auth_code_store_mock = Mock(spec=AuthCodeStore)
        auth_code_store_mock.fetch_by_code.return_value = None

        client_mock = Mock(Client)
        client_mock.secret = client_secret
        client_mock.redirect_uris = [redirect_uri]

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               code, redirect_uri]

        handler = AuthorizationCodeTokenHandler(
            access_token_store=Mock(spec=AccessTokenStore),
            auth_token_store=auth_code_store_mock,
            client_store=client_store_mock,
            token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation,
                         "Invalid authorization code parameter")

    def test_read_validate_params_wrong_redirect_uri_in_code_data(self):
        client_id = "abc"
        client_secret = "t%gH"
        code = "xyz"
        redirect_uri_actual = "http://invalid-callback"
        redirect_uri_expected = "http://callback"

        auth_code_mock = Mock(AuthorizationCode)
        auth_code_mock.code = code
        auth_code_mock.redirect_uri = redirect_uri_actual

        auth_code_store_mock = Mock(spec=AuthCodeStore)
        auth_code_store_mock.fetch_by_code.return_value = auth_code_mock

        client_mock = Mock(Client)
        client_mock.secret = client_secret
        client_mock.redirect_uris = [redirect_uri_expected]

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               code, redirect_uri_expected]

        handler = AuthorizationCodeTokenHandler(
            access_token_store=Mock(spec=AccessTokenStore),
            auth_token_store=auth_code_store_mock,
            client_store=client_store_mock,
            token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation, "Invalid redirect_uri parameter")

    def test_read_validate_params_token_expired(self):
        client_id = "abc"
        client_secret = "t%gH"
        code = "xyz"
        redirect_uri = "http://callback"

        auth_code_mock = Mock(AuthorizationCode)
        auth_code_mock.code = code
        auth_code_mock.redirect_uri = redirect_uri
        auth_code_mock.is_expired.return_value = True

        auth_code_store_mock = Mock(spec=AuthCodeStore)
        auth_code_store_mock.fetch_by_code.return_value = auth_code_mock

        client_mock = Mock(Client)
        client_mock.secret = client_secret
        client_mock.redirect_uris = [redirect_uri]

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               code, redirect_uri]

        handler = AuthorizationCodeTokenHandler(
            access_token_store=Mock(spec=AccessTokenStore),
            auth_token_store=auth_code_store_mock,
            client_store=client_store_mock,
            token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        self.assertEqual(error.error, "invalid_grant")
        self.assertEqual(error.explanation, "Authorization code has expired")

    def test_process_no_refresh_token(self):
        token_data = {"access_token": "abcd", "token_type": "Bearer"}
        client_id = "efg"
        data = {"additional": "data"}
        scopes = ["scope"]

        access_token_store_mock = Mock(spec=AccessTokenStore)
        auth_code_store_mock = Mock(spec=AuthCodeStore)
        client_store_mock = Mock(spec=ClientStore)

        token_generator_mock = Mock(spec=TokenGenerator)
        token_generator_mock.create_access_token_data.return_value = token_data

        response_mock = Mock(spec=Response)
        response_mock.body = None
        response_mock.status_code = None

        handler = AuthorizationCodeTokenHandler(
            access_token_store=access_token_store_mock,
            auth_token_store=auth_code_store_mock,
            client_store=client_store_mock,
            token_generator=token_generator_mock)
        handler.client_id = client_id
        handler.data = data
        handler.scopes = scopes
        response = handler.process(Mock(spec=Request), response_mock, {})

        self.assertIsNotNone(auth_code_store_mock.delete_code.call_args)
        access_token, = access_token_store_mock.save_token.call_args[0]
        self.assertTrue(isinstance(access_token, AccessToken))
        self.assertEqual(access_token.data, data)
        self.assertEqual(access_token.grant_type, "authorization_code")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, json.dumps(token_data))
        response_mock.add_header.assert_called_with("Content-Type",
                                                    "application/json")
    @patch("time.time", mock_time)
    def test_process_with_refresh_token(self):
        token_data = {"access_token": "abcd", "token_type": "Bearer",
                      "refresh_token": "wxyz", "expires_in": 600}
        client_id = "efg"
        data = {"additional": "data"}
        scopes = ["scope"]

        access_token_store_mock = Mock(spec=AccessTokenStore)
        auth_code_store_mock = Mock(spec=AuthCodeStore)
        client_store_mock = Mock(spec=ClientStore)

        token_generator_mock = Mock(spec=TokenGenerator)
        token_generator_mock.create_access_token_data.return_value = token_data

        response_mock = Mock(spec=Response)
        response_mock.body = None
        response_mock.status_code = None

        handler = AuthorizationCodeTokenHandler(
            access_token_store=access_token_store_mock,
            auth_token_store=auth_code_store_mock,
            client_store=client_store_mock,
            token_generator=token_generator_mock)
        handler.client_id = client_id
        handler.data = data
        handler.scopes = scopes
        response = handler.process(Mock(spec=Request), response_mock, {})

        self.assertIsNotNone(auth_code_store_mock.delete_code.call_args)
        access_token, = access_token_store_mock.save_token.call_args[0]
        self.assertTrue(isinstance(access_token, AccessToken))
        self.assertEqual(access_token.data, data)
        self.assertEqual(access_token.grant_type, "authorization_code")
        self.assertEqual(access_token.expires_at, 1600)
        self.assertEqual(access_token.refresh_token,
                         token_data["refresh_token"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, json.dumps(token_data))
        response_mock.add_header.assert_called_with("Content-Type",
                                                    "application/json")

class ImplicitGrantTestCase(unittest.TestCase):
    def test_create_matching_response_type(self):
        path = "/auth"

        request_mock = Mock(spec=Request)
        request_mock.path = path
        request_mock.get_param.return_value = "token"

        client_store_mock = Mock()
        site_adapter_mock = Mock()
        token_generator_mock = Mock()

        server_mock = Mock()
        server_mock.authorize_path = path
        server_mock.client_store = client_store_mock
        server_mock.site_adapter = site_adapter_mock
        server_mock.token_generator = token_generator_mock

        factory = ImplicitGrant()
        result_class = factory(request_mock, server_mock)

        request_mock.get_param.assert_called_with("response_type")
        self.assertTrue(isinstance(result_class, ImplicitGrantHandler))

    def test_create_not_matching_response_type(self):
        request_mock = Mock(spec=Request)
        request_mock.get_param.return_value = "something"

        server_mock = Mock()

        factory = ImplicitGrant()
        result_class = factory(request_mock, server_mock)

        request_mock.get_param.assert_called_with("response_type")
        self.assertEqual(result_class, None)

class ImplicitGrantHandlerTestCase(unittest.TestCase):
    def test_process_redirect_with_token(self):
        client_id = "abc"
        environ = {"session": "data"}
        redirect_uri = "http://callback"
        scopes = ["scopes"]
        token = "tokencode"
        user_data = ({}, 1)

        access_token_store_mock = Mock(spec=AccessTokenStore)

        request_mock = Mock(spec=Request)

        responseMock = Mock(spec=Response)

        scope_handler_mock = Mock(Scope)
        scope_handler_mock.scopes = scopes
        scope_handler_mock.send_back = False

        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.return_value = user_data

        token_generator_mock = Mock(spec=["generate"])
        token_generator_mock.generate.return_value = token

        redirect_uri_with_token = "%s#access_token=%s&token_type=bearer" % (redirect_uri, token)

        handler = ImplicitGrantHandler(
            access_token_store=access_token_store_mock, client_store=Mock(),
            scope_handler=scope_handler_mock, site_adapter=site_adapter_mock,
            token_generator=token_generator_mock
        )
        handler.client_id = client_id
        handler.redirect_uri = redirect_uri
        result_response = handler.process(request_mock, responseMock, environ)

        site_adapter_mock.authenticate.assert_called_with(request_mock,
                                                          environ, scopes)

        access_token, = access_token_store_mock.save_token.call_args[0]
        self.assertTrue(isinstance(access_token, AccessToken))
        self.assertEqual(access_token.grant_type, "implicit")

        responseMock.add_header.assert_called_with("Location",
                                                   redirect_uri_with_token)
        self.assertEqual(responseMock.status_code, 302)
        self.assertEqual(responseMock.content, "")
        self.assertEqual(result_response, responseMock)


    def test_process_redirect_with_state(self):
        """
        ImplicitGrantHandler should include the value of the "state" query parameter from request in redirect
        """
        client_id = "abc"
        redirect_uri = "http://callback"
        state = "XHGFI"
        token = "tokencode"
        user_data = ({}, 1)

        expected_redirect_uri = "%s#access_token=%s&token_type=bearer&state=%s" % (redirect_uri, token, state)

        response_mock = Mock(spec=Response)

        scope_handler_mock = Mock(Scope)
        scope_handler_mock.scopes = []
        scope_handler_mock.send_back = False

        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.return_value = user_data

        token_generator_mock = Mock(spec=["generate"])
        token_generator_mock.generate.return_value = token

        handler = ImplicitGrantHandler(
            access_token_store=Mock(AccessTokenStore), client_store=Mock(),
            scope_handler=scope_handler_mock,
            site_adapter=site_adapter_mock,
            token_generator=token_generator_mock)
        handler.client_id = client_id
        handler.redirect_uri = redirect_uri
        handler.state = state

        result_response = handler.process(request=Mock(spec=Request),
                                          response=response_mock, environ={})

        response_mock.add_header.assert_called_with("Location",
                                                   expected_redirect_uri)
        self.assertEqual(response_mock.status_code, 302)
        self.assertEqual(response_mock.content, "")
        self.assertEqual(result_response, response_mock)

    def test_process_with_scope(self):
        client_id = "abc"
        redirect_uri = "http://callback"
        scopes = ["scope_read", "scope_write"]
        scopes_uri = "%20".join(scopes)
        state = "XHGFI"
        token = "tokencode"

        expected_redirect_uri = "%s#access_token=%s&token_type=bearer&state=%s&scope=%s" % (redirect_uri, token, state, scopes_uri)

        response_mock = Mock(spec=Response)

        scope_handler_mock = Mock(Scope)
        scope_handler_mock.scopes = scopes
        scope_handler_mock.send_back = True

        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.return_value = ({}, 1)

        token_generator_mock = Mock(spec=["generate"])
        token_generator_mock.generate.return_value = token

        handler = ImplicitGrantHandler(
            access_token_store=Mock(AccessTokenStore), client_store=Mock(),
            scope_handler=scope_handler_mock,
            site_adapter=site_adapter_mock,
            token_generator=token_generator_mock)
        handler.client_id = client_id
        handler.redirect_uri = redirect_uri
        handler.state = state

        result_response = handler.process(request=Mock(spec=Request),
                                          response=response_mock, environ={})

        response_mock.add_header.assert_called_with("Location",
                                                   expected_redirect_uri)
        self.assertEqual(response_mock.status_code, 302)
        self.assertEqual(response_mock.content, "")
        self.assertEqual(result_response, response_mock)

    def test_process_unconfirmed(self):
        scopes = ["scopes"]
        environ = {"session": "data"}

        request_mock = Mock(spec=Request)

        response_mock = Mock(spec=Response)

        scope_handler_mock = Mock(Scope)
        scope_handler_mock.scopes = scopes

        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.side_effect = UserNotAuthenticated
        site_adapter_mock.render_auth_page.return_value = response_mock

        handler = ImplicitGrantHandler(
            Mock(spec=AccessTokenStore), client_store=Mock(),
            scope_handler=scope_handler_mock, site_adapter=site_adapter_mock,
            token_generator=Mock()
        )
        result_response = handler.process(request_mock, response_mock, environ)

        site_adapter_mock.authenticate.assert_called_with(request_mock,
                                                          environ, scopes)
        site_adapter_mock.render_auth_page.assert_called_with(request_mock,
                                                              response_mock,
                                                              environ,
                                                              scopes)
        self.assertEqual(result_response, response_mock)

    def test_redirect_oauth_error(self):
        error_code = "error_code"
        client_id = "cid"
        redirect_uri = "https://callback"
        scope = "scope"
        state = "state"
        expected_redirect_location = "%s#error=%s" % (redirect_uri, error_code)

        client_mock = Mock(Client)
        client_mock.redirect_uris = [redirect_uri]
        client_mock.has_redirect_uri.return_value = True

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        error_mock = Mock(spec=OAuthUserError)
        error_mock.error = error_code

        request_mock = Mock(spec=Request)
        request_mock.get_param.side_effect = [client_id, redirect_uri, scope,
                                             state]

        response_mock = Mock(spec=Response)

        handler = ImplicitGrantHandler(
            Mock(spec=AccessTokenStore), client_store=client_store_mock,
            scope_handler=Mock(Scope), site_adapter=Mock(),
            token_generator=Mock()
        )
        handler.read_validate_params(request_mock)
        altered_response = handler.redirect_oauth_error(error_mock,
                                                        response_mock)

        response_mock.add_header.assert_called_with("Location",
                                                    expected_redirect_location)
        self.assertEqual(altered_response.status_code, 302)
        self.assertEqual(altered_response.body, "")

class ResourceOwnerGrantTestCase(unittest.TestCase):
    def test_call(self):
        request_mock = Mock(Request)
        request_mock.post_param.return_value = "password"

        access_token_store_mock = Mock(AccessTokenStore)
        client_store_mock = Mock(ClientStore)
        site_adapter_mock = Mock(SiteAdapter)
        token_generator_mock = Mock()

        server_mock = Mock(Provider)
        server_mock.access_token_store = access_token_store_mock
        server_mock.client_store = client_store_mock
        server_mock.site_adapter = site_adapter_mock
        server_mock.token_generator = token_generator_mock

        factory = ResourceOwnerGrant()

        handler = factory(request_mock, server_mock)

        request_mock.post_param.assert_called_with("grant_type")
        self.assertTrue(isinstance(handler, ResourceOwnerGrantHandler))

    def test_call_no_resource_request(self):
        request_mock = Mock(Request)
        request_mock.post_param.return_value = "other"

        server_mock = Mock(Provider)

        factory = ResourceOwnerGrant()

        handler = factory(request_mock, server_mock)

        request_mock.post_param.assert_called_with("grant_type")
        self.assertEqual(handler, None)

class ResourceOwnerGrantHandlerTestCase(unittest.TestCase):
    def test_process(self):
        access_token = "0aef"
        client_id = "abcd"
        expected_response_body = {"access_token": access_token,
                                  "token_type": "Bearer"}
        scopes = ["scope"]
        token_data = {"access_token": access_token, "token_type": "Bearer"}
        user = {"id": 123}

        access_token_store_mock = Mock(AccessTokenStore)

        request_mock = Mock(Request)

        response_mock = Mock(Response)

        scope_handler_mock = Mock(Scope)
        scope_handler_mock.scopes = scopes
        scope_handler_mock.send_back = False

        site_adapter_mock = Mock(SiteAdapter)
        site_adapter_mock.authenticate.return_value = user

        token_generator_mock = Mock(spec=TokenGenerator)
        token_generator_mock.create_access_token_data.return_value = token_data

        handler = ResourceOwnerGrantHandler(access_token_store_mock,
                                            Mock(ClientStore),
                                            scope_handler_mock,
                                            site_adapter_mock,
                                            token_generator_mock)
        handler.client_id = client_id
        result = handler.process(request_mock, response_mock, {})

        site_adapter_mock.authenticate.assert_called_with(request_mock, {},
                                                          scopes)
        token_generator_mock.create_access_token_data.assert_called_with()
        access_token, = access_token_store_mock.save_token.call_args[0]
        self.assertTrue(isinstance(access_token, AccessToken))
        self.assertEqual(access_token.grant_type,
                         ResourceOwnerGrant.grant_type)
        response_mock.add_header.assert_called_with("Content-Type",
                                                    "application/json")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(json.loads(result.body), expected_response_body)
        self.assertEqual(result, response_mock)

    @patch("time.time", mock_time)
    def test_process_with_refresh_token(self):
        access_token = "0aef"
        client_id = "abcd"
        expected_response_body = {"access_token": access_token,
                                  "token_type": "Bearer",
                                  "refresh_token": "wxyz", "expires_in": 600}
        scopes = ["scope"]
        token_data = {"access_token": access_token, "token_type": "Bearer",
                      "refresh_token": "wxyz", "expires_in": 600}
        user = {"id": 123}

        access_token_store_mock = Mock(AccessTokenStore)

        request_mock = Mock(Request)

        response_mock = Mock(Response)

        scope_handler_mock = Mock(Scope)
        scope_handler_mock.scopes = scopes
        scope_handler_mock.send_back = False

        site_adapter_mock = Mock(SiteAdapter)
        site_adapter_mock.authenticate.return_value = user

        token_generator_mock = Mock(spec=TokenGenerator)
        token_generator_mock.create_access_token_data.return_value = token_data

        handler = ResourceOwnerGrantHandler(access_token_store_mock,
                                            Mock(ClientStore),
                                            scope_handler_mock,
                                            site_adapter_mock,
                                            token_generator_mock)
        handler.client_id = client_id
        result = handler.process(request_mock, response_mock, {})

        site_adapter_mock.authenticate.assert_called_with(request_mock, {},
                                                          scopes)
        token_generator_mock.create_access_token_data.assert_called_with()
        access_token, = access_token_store_mock.save_token.call_args[0]
        self.assertTrue(isinstance(access_token, AccessToken))
        self.assertEqual(access_token.refresh_token, token_data["refresh_token"])
        self.assertEqual(access_token.expires_at, 1600)
        response_mock.add_header.assert_called_with("Content-Type",
                                                    "application/json")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(json.loads(result.body), expected_response_body)
        self.assertEqual(result, response_mock)

    def test_process_redirect_with_scope(self):
        access_token = "0aef"
        client_id = "abcd"
        scopes = ["scope_read", "scope_write"]
        expected_response_body = {"access_token": access_token,
                                  "token_type": "Bearer",
                                  "scope": " ".join(scopes)}
        token_data = {"access_token": access_token, "token_type": "Bearer"}

        response_mock = Mock(Response)

        scope_handler_mock = Mock(Scope)
        scope_handler_mock.scopes = scopes
        scope_handler_mock.send_back = True

        token_generator_mock = Mock(spec=TokenGenerator)
        token_generator_mock.create_access_token_data.return_value = token_data

        handler = ResourceOwnerGrantHandler(Mock(AccessTokenStore),
                                            Mock(ClientStore),
                                            scope_handler_mock,
                                            Mock(SiteAdapter),
                                            token_generator_mock)
        handler.client_id = client_id
        result = handler.process(Mock(Request), response_mock, {})

        token_generator_mock.create_access_token_data.assert_called_with()
        response_mock.add_header.assert_called_with("Content-Type",
                                                    "application/json")
        self.assertEqual(result.status_code, 200)
        self.assertDictEqual(expected_response_body, json.loads(result.body))
        self.assertEqual(result, response_mock)

    def test_read_validate_params(self):
        client_id = "abcd"
        client_secret = "xyz"
        password = "johnpw"
        username = "johndoe"

        client_mock = Mock(Client)
        client_mock.secret = client_secret

        client_store_mock = Mock(ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        request_mock = Mock(Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               password, username]

        scope_handler_mock = Mock(Scope)

        handler = ResourceOwnerGrantHandler(Mock(AccessTokenStore),
                                            client_store_mock,
                                            scope_handler_mock,
                                            Mock(SiteAdapter),
                                            Mock())
        result = handler.read_validate_params(request_mock)

        client_store_mock.fetch_by_client_id.assert_called_with(client_id)
        scope_handler_mock.parse.assert_called_with(request=request_mock,
                                                    source="body")

        self.assertEqual(handler.client_id, client_id)
        self.assertEqual(handler.username, username)
        self.assertEqual(handler.password, password)
        self.assertTrue(result)

    def test_read_validate_params_no_client_id(self):
        request_mock = Mock(Request)
        request_mock.post_param.return_value = None

        handler = ResourceOwnerGrantHandler(Mock(AccessTokenStore),
                                            Mock(ClientStore), Mock(Scope),
                                            Mock(SiteAdapter), Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        request_mock.post_param.assert_called_with("client_id")
        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation, "Missing client_id parameter")

    def test_read_validate_params_unknown_client_id(self):
        client_id = "abcd"

        client_store_mock = Mock(ClientStore)
        client_store_mock.fetch_by_client_id.side_effect = ClientNotFoundError

        request_mock = Mock(Request)
        request_mock.post_param.return_value = client_id

        handler = ResourceOwnerGrantHandler(Mock(AccessTokenStore),
                                            client_store_mock, Mock(Scope),
                                            Mock(SiteAdapter), Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        request_mock.post_param.assert_called_with("client_id")
        client_store_mock.fetch_by_client_id.assert_called_with(client_id)
        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation, "Unknown client")

    def test_read_validate_params_invalid_client_secret(self):
        client_id = "abcd"
        client_secret_actual = "foo"
        client_secret_expected = "xyz"

        client_mock = Mock(Client)
        client_mock.secret = client_secret_expected

        client_store_mock = Mock(ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client_mock

        request_mock = Mock(Request)
        request_mock.post_param.side_effect = [client_id, client_secret_actual]

        handler = ResourceOwnerGrantHandler(Mock(AccessTokenStore),
                                            client_store_mock,
                                            Mock(Scope),
                                            Mock(SiteAdapter),
                                            Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        error = expected.exception

        request_mock.post_param.assert_has_calls([call("client_id"),
                                                  call("client_secret")])
        client_store_mock.fetch_by_client_id.assert_called_with(client_id)
        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation, "Could not authenticate client")

class ScopeTestCase(unittest.TestCase):
    def test_parse_scope_scope_present_in_query(self):
        """
        Scope.parse should return a list of requested scopes
        """
        expected_scopes = ["friends_read", "user_read"]

        request_mock = Mock(Request)
        request_mock.get_param.return_value = "friends_read user_read"

        scope = Scope(available=["user_read", "friends_write", "friends_read"])

        scope.parse(request=request_mock, source="query")

        request_mock.get_param.assert_called_with("scope")

        self.assertListEqual(expected_scopes, scope.scopes)
        self.assertFalse(scope.send_back)

    def test_parse_scope_scope_present_in_body(self):
        scope = Scope()

        request_mock = Mock(Request)
        request_mock.post_param.return_value = None

        scope.parse(request=request_mock, source="body")

        request_mock.post_param.assert_called_with("scope")

    def test_parse_scope_default_on_no_scope(self):
        """
        Scope.parse should return a list containing the default value if no scope present in request and default is set
        """
        expected_scopes = ["all"]

        request_mock = Mock(Request)
        request_mock.get_param.return_value = None

        scope = Scope(available=["user_read", "friends_write", "friends_read"],
                      default="all")

        scope.parse(request=request_mock, source="query")

        request_mock.get_param.assert_called_with("scope")

        self.assertListEqual(expected_scopes, scope.scopes)
        self.assertTrue(scope.send_back)

    def test_parse_scope_default_on_no_matching_scopes(self):
        """
        Scope.parse should return a list containing the default value if scope in request does not match and default is set
        """
        expected_scopes = ["all"]

        request_mock = Mock(Request)
        request_mock.get_param.return_value = "user_write"

        scope = Scope(available=["user_read", "friends_write", "friends_read"],
                      default="all")

        scope.parse(request=request_mock, source="query")

        request_mock.get_param.assert_called_with("scope")

        self.assertListEqual(expected_scopes, scope.scopes)
        self.assertTrue(scope.send_back)

    def test_parse_scope_no_value_on_no_scope_no_default(self):
        """
        Scope.parse should return an empty list if no scope is present in request and no default or scapes are defined
        """
        expected_scopes = []

        request_mock = Mock(Request)
        request_mock.get_param.return_value = None

        scope = Scope()

        scope.parse(request=request_mock, source="query")

        request_mock.get_param.assert_called_with("scope")

        self.assertEqual(expected_scopes, scope.scopes)
        self.assertFalse(scope.send_back)

    def test_parse_scope_exception_on_available_scopes_no_scope_given(self):
        """
        Scope.parse should throw an OAuthError if no scope is present in request but scopes are defined
        """
        request_mock = Mock(Request)
        request_mock.get_param.return_value = None

        scope = Scope(available=["user_read", "friends_write", "friends_read"])

        with self.assertRaises(OAuthInvalidError) as expected:
            scope.parse(request_mock, source="query")

        e = expected.exception

        self.assertEqual(e.error, "invalid_scope")

    def test_compare_scopes_equal(self):
        """
        Scope.compare should use the same scopes if new and old scopes do not differ
        """
        scope = Scope(available=["a", "b"])

        scope.scopes = ["a", "b"]

        result = scope.compare(["a", "b"])

        self.assertTrue(result)
        self.assertListEqual(scope.scopes, ["a", "b"])

    def test_compare_valid_scope_subset(self):
        """
        Scope.compare should set a new value for scopes attribute if the new scopes are a subset of the previously issued scopes
        """
        scope = Scope(available=["a", "b", "c"])

        scope.scopes = ["b", "c"]

        result = scope.compare(["a", "b", "c"])

        self.assertTrue(result)
        self.assertListEqual(scope.scopes, ["b", "c"])

    def test_compare_invalid_scope_requested(self):
        """
        Scope.compare should thow an error if a scope is requested that is not contained in the previous scopes.
        """
        scope = Scope(available=["a", "b", "c"])

        scope.scopes = ["b", "c"]

        with self.assertRaises(OAuthInvalidError) as expected:
            scope.compare(["a", "b"])

        e = expected.exception

        self.assertEqual(e.error, "invalid_scope")

class RefreshTokenTestCase(unittest.TestCase):
    def test_call(self):
        """
        RefreshToken should create a new instance of RefreshTokenHandler
        """
        path = "/token"
        expires_in = 600

        access_token_store_mock = Mock()
        client_store_mock = Mock()
        scope_handler_mock = Mock()
        token_generator_mock = Mock()

        controller_mock = Mock(spec=Provider)
        controller_mock.token_path = path
        controller_mock.access_token_store = access_token_store_mock
        controller_mock.client_store = client_store_mock
        controller_mock.scope_handler = scope_handler_mock
        controller_mock.token_generator = token_generator_mock
        controller_mock.tokens_expire_in = expires_in

        request_mock = Mock(spec=Request)
        request_mock.path = path
        request_mock.post_param.return_value = "refresh_token"

        grant = RefreshToken(expires_in=0)

        grant_handler = grant(request_mock, controller_mock)

        request_mock.post_param.assert_called_with("grant_type")

        self.assertTrue(isinstance(grant_handler, RefreshTokenHandler))
        self.assertTrue(isinstance(grant_handler.scope_handler, Scope))
        self.assertEqual(access_token_store_mock,
                         grant_handler.access_token_store)
        self.assertEqual(client_store_mock, grant_handler.client_store)
        self.assertEqual(token_generator_mock, grant_handler.token_generator)

    def test_call_wrong_path(self):
        """
        RefreshToken should return 'None' if path in the request does not equal the token path
        """
        controller_mock = Mock(spec=Provider)
        controller_mock.token_path = "/token"

        request_mock = Mock(spec=Request)
        request_mock.path = "/authorize"

        grant = RefreshToken(expires_in=0)

        grant_handler = grant(request_mock, controller_mock)

        self.assertEqual(grant_handler, None)

    def test_call_other_grant_type(self):
        """
        RefreshToken should return 'None' if another grant type is requested
        """
        path = "/token"

        controller_mock = Mock(spec=Provider)
        controller_mock.token_path = path

        request_mock = Mock(spec=Request)
        request_mock.path = path
        request_mock.get_param.return_value = "authorization_code"

        grant = RefreshToken(expires_in=0)

        grant_handler = grant(request_mock, controller_mock)

        self.assertEqual(grant_handler, None)

class RefreshTokenHandlerTestCase(unittest.TestCase):
    @patch("time.time", mock_time)
    def test_process(self):
        client_id = "testclient"
        data = {"additional": "data"}
        expires_in = 600
        scopes = []
        token = "abcdefg"
        expected_response_body = {"access_token": token,
                                  "expires_in": expires_in,
                                  "token_type": "Bearer"}
        expected_headers = {"Content-type": "application/json"}

        access_token_store_mock = Mock(spec=AccessTokenStore)

        response = Response()

        scope_handler_mock = Mock(spec=Scope)
        scope_handler_mock.scopes = scopes

        token_generator_mock = Mock(spec=["generate"])
        token_generator_mock.expires_in = expires_in
        token_generator_mock.generate.return_value = token

        handler = RefreshTokenHandler(access_token_store=access_token_store_mock,
                                      client_store=Mock(spec=ClientStore),
                                      scope_handler=scope_handler_mock,
                                      token_generator=token_generator_mock)
        handler.client_id = client_id
        handler.data = data

        result = handler.process(request=Mock(spec=Request),
                                 response=response, environ={})

        access_token, = access_token_store_mock.save_token.call_args[0]
        self.assertEqual(access_token.client_id, client_id)
        self.assertEqual(access_token.grant_type, "refresh_token")
        self.assertDictEqual(access_token.data, data)
        self.assertEqual(access_token.token, token)
        self.assertListEqual(access_token.scopes, scopes)
        self.assertEqual(access_token.expires_at, 1600)

        self.assertEqual(result, response)
        self.assertDictContainsSubset(expected_headers, result.headers)
        self.assertEqual(json.dumps(expected_response_body), result.body)

    @patch("time.time", mock_time)
    def test_read_validate_params(self):
        client_id = "client"
        client_secret = "secret"
        data = {"additional": "data"}
        original_token = "sd3f3j"
        refresh_token = "s74jf"
        scopes = []

        access_token = AccessToken(client_id=client_id, token=original_token,
                                   grant_type=RefreshToken.grant_type,
                                   data=data, expires_at=1234, scopes=scopes)

        access_token_store_mock = Mock(AccessTokenStore)
        access_token_store_mock.fetch_by_refresh_token.return_value = access_token

        client = Client(identifier=client_id, secret=client_secret,
                        redirect_uris=[])

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               refresh_token]

        scope_handler_mock = Mock(spec=Scope)

        handler = RefreshTokenHandler(access_token_store=access_token_store_mock,
                                      client_store=client_store_mock,
                                      scope_handler=scope_handler_mock,
                                      token_generator=Mock())

        handler.read_validate_params(request=request_mock)

        request_mock.post_param.assert_has_calls([call("client_id"),
                                                  call("client_secret"),
                                                  call("refresh_token")])
        access_token_store_mock.fetch_by_refresh_token.assert_called_with(refresh_token)
        client_store_mock.fetch_by_client_id.assert_called_with(client_id)
        scope_handler_mock.parse.assert_called_with(request_mock, "body")
        scope_handler_mock.compare.assert_called_with(scopes)

        self.assertEqual(handler.client_id, client_id)
        self.assertEqual(handler.data, data)
        self.assertEqual(handler.refresh_token, refresh_token)


    def test_read_validate_params_no_client_id(self):
        request_mock = Mock(spec=Request)
        request_mock.post_param.return_value = None

        handler = RefreshTokenHandler(access_token_store=Mock(),
                                      client_store=Mock(),
                                      scope_handler=Mock(),
                                      token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        e = expected.exception

        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "Missing client_id in request body")

    def test_read_validate_params_no_client_secret(self):
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = ["abc", None]

        handler = RefreshTokenHandler(access_token_store=Mock(),
                                      client_store=Mock(),
                                      scope_handler=Mock(),
                                      token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        e = expected.exception

        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "Missing client_secret in request body")

    def test_read_validate_params_no_refresh_token(self):
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = ["abc", "xyz", None]

        handler = RefreshTokenHandler(access_token_store=Mock(),
                                      client_store=Mock(),
                                      scope_handler=Mock(),
                                      token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        e = expected.exception

        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "Missing refresh_token in request body")

    def test_read_validate_params_client_not_found(self):
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = ["abc", "xyz", "uuu"]

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.side_effect = ClientNotFoundError

        handler = RefreshTokenHandler(access_token_store=Mock(),
                                      client_store=client_store_mock,
                                      scope_handler=Mock(),
                                      token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        e = expected.exception

        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "Unknown client")

    def test_read_validate_params_invalid_client_secret(self):
        client_id = "abc"
        secret_expected = "mno"
        secret_actual = "xyz"

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, secret_actual, "uuu"]

        client = Client(identifier=client_id, secret=secret_expected,
                        redirect_uris=[])

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client

        handler = RefreshTokenHandler(access_token_store=Mock(),
                                      client_store=client_store_mock,
                                      scope_handler=Mock(),
                                      token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        e = expected.exception

        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "Invalid client secret")

    def test_read_validate_params_invalid_refresh_token(self):
        client_id = "abc"
        secret = "xyz"

        access_token_store_mock = Mock(spec=AccessTokenStore)
        access_token_store_mock.fetch_by_refresh_token.side_effect = AccessTokenNotFound

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, secret, "uuu"]

        client = Client(identifier=client_id, secret=secret, redirect_uris=[])

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client

        handler = RefreshTokenHandler(access_token_store=access_token_store_mock,
                                      client_store=client_store_mock,
                                      scope_handler=Mock(),
                                      token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        e = expected.exception

        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "Invalid refresh token")

    @patch("time.time", mock_time)
    def test_read_validate_params_expired_access_token(self):
        client_id = "abc"
        secret = "xyz"

        access_token_mock = Mock(spec=AccessToken)
        access_token_mock.expires_at = 900

        access_token_store_mock = Mock(spec=AccessTokenStore)
        access_token_store_mock.fetch_by_refresh_token.return_value = access_token_mock

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, secret, "uuu"]

        client = Client(identifier=client_id, secret=secret, redirect_uris=[])

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = client

        handler = RefreshTokenHandler(access_token_store=access_token_store_mock,
                                      client_store=client_store_mock,
                                      scope_handler=Mock(),
                                      token_generator=Mock())

        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)

        e = expected.exception

        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "Invalid refresh token")

class ClientCredentialsGrantTestCase(unittest.TestCase):
    def test_call(self):
        token_path = "token"

        request_mock = Mock(spec=Request)
        request_mock.path = token_path
        request_mock.post_param.return_value = "client_credentials"

        access_token_store_mock = Mock()
        client_store_mock = Mock()
        token_generator_mock = Mock()

        scope_handler_mock = Mock(spec=Scope)

        server_mock = Mock()
        server_mock.token_path = token_path
        server_mock.access_token_store = access_token_store_mock
        server_mock.client_store = client_store_mock
        server_mock.scope_handler = scope_handler_mock
        server_mock.token_generator = token_generator_mock

        grant = ClientCredentialsGrant()
        handler = grant(request_mock, server_mock)

        request_mock.post_param.assert_called_with("grant_type")
        self.assertTrue(isinstance(handler, ClientCredentialsHandler))
        self.assertEqual(handler.access_token_store, access_token_store_mock)
        self.assertEqual(handler.client_store, client_store_mock)
        self.assertTrue(isinstance(handler.scope_handler, Scope))
        self.assertEqual(handler.token_generator, token_generator_mock)

    def test_call_wrong_request_path(self):
        request_mock = Mock(spec=Request)
        request_mock.path = "authorize"

        server_mock = Mock()
        server_mock.token_path = "token"

        grant = ClientCredentialsGrant()
        handler = grant(request_mock, server_mock)

        self.assertEqual(handler, None)

    def test_call_other_grant_type(self):
        token_path = "token"

        request_mock = Mock(spec=Request)
        request_mock.path = token_path
        request_mock.post_param.return_value = "other_grant"

        server_mock = Mock()
        server_mock.token_path = token_path

        grant = ClientCredentialsGrant()
        handler = grant(request_mock, server_mock)

        self.assertEqual(handler, None)

class ClientCredentialsHandlerTestCase(unittest.TestCase):
    @patch("time.time", mock_time)
    def test_process(self):
        client_id = "xyz"
        expires_in = 600
        token = "abcd"
        scopes = ["foo", "bar"]

        expected_response_body = {"access_token": token,
                                  "expires_in": expires_in,
                                  "token_type": "Bearer",
                                  "scope": scopes}

        access_token_store_mock = Mock(spec=AccessTokenStore)

        response_mock = Mock(spec=Response)

        scope_handler_mock = Mock(spec=Scope)
        scope_handler_mock.send_back = True
        scope_handler_mock.scopes = scopes

        token_generator_mock = Mock(spec=TokenGenerator)
        token_generator_mock.generate.return_value = token
        token_generator_mock.expires_in = expires_in

        handler = ClientCredentialsHandler(
            access_token_store=access_token_store_mock,
            client_store=Mock(),
            scope_handler=scope_handler_mock,
            token_generator=token_generator_mock)
        handler.client_id = client_id
        result_response = handler.process(request=Mock(),
                                          response=response_mock, environ={})

        access_token, = access_token_store_mock.save_token.call_args[0]
        self.assertTrue(isinstance(access_token, AccessToken))
        self.assertEqual(access_token.client_id, client_id)
        self.assertEqual(access_token.grant_type, "client_credentials")
        self.assertEqual(access_token.token, token)
        self.assertEqual(access_token.data, {})
        self.assertEqual(access_token.expires_at, expires_in + 1000)
        self.assertEqual(access_token.refresh_token, None)
        self.assertEqual(access_token.scopes, scopes)

        response_mock.add_header.assert_called_with("Content-type",
                                                    "application/json")
        self.assertDictEqual(json.loads(result_response.body),
                             expected_response_body)

    def test_read_validate_params(self):
        client_id = "abc"
        client_secret = "xyz"

        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = Client(
            identifier=client_id,
            secret=client_secret,
            redirect_uris=[])

        scope_handler_mock = Mock(spec=Scope)

        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret]

        handler = ClientCredentialsHandler(access_token_store=Mock(),
                                           client_store=client_store_mock,
                                           scope_handler=scope_handler_mock,
                                           token_generator=Mock())
        handler.read_validate_params(request_mock)

        client_store_mock.fetch_by_client_id.assert_called_with(client_id)
        request_mock.post_param.assert_has_calls([call("client_id"),
                                                  call("client_secret")])
        scope_handler_mock.parse.assert_called_with(request=request_mock,
                                                    source="body")

if __name__ == "__main__":
    unittest.main()
