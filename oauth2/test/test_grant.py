from mock import Mock, call
import json
import unittest
from oauth2.web import Request, Response, SiteAdapter
from oauth2.grant import ImplicitGrantHandler, AuthorizationCodeAuthHandler,\
    AuthRequestMixin, AuthorizationCodeTokenHandler, ImplicitGrant,\
    AuthorizationCodeGrant, ResourceOwnerGrantHandler, ResourceOwnerGrant
from oauth2.store import ClientStore, AuthTokenStore, AccessTokenStore
from oauth2.error import OAuthInvalidError, OAuthUserError, OAuthClientError

# Mock datetime.now()
# see http://stackoverflow.com/questions/4481954/python-trying-to-mock-datetime-date-today-but-not-working
import datetime
from oauth2 import AuthorizationController
class DatetimeMock(datetime.datetime):
    @classmethod
    def now(cls):
        return cls(1990, 1, 1, 0, 0, 0)
datetime.datetime = DatetimeMock

class AuthrizationCodeGrantTestCase(unittest.TestCase):
    def test_create_auth_handler(self):
        path = "/auth"
        
        request_mock = Mock(spec=Request)
        request_mock.path = path
        request_mock.get_param.return_value = "code"
        
        server_mock = Mock()
        server_mock.authorize_path = path
        server_mock.auth_token_store = Mock()
        server_mock.client_store = Mock()
        server_mock.site_adapter = Mock()
        server_mock.token_generator = Mock()
        
        factory = AuthorizationCodeGrant()
        result_class = factory(request_mock, server_mock)
        
        request_mock.get_param.assert_called_with("response_type")
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
        server_mock.auth_token_store = Mock()
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
        client_id    = "cid"
        redirect_uri = "http://somewhere"
        scope        = "scope"
        state        = "state"
        
        request_mock = Mock(spec=Request)
        request_mock.get_param.side_effect = [client_id, redirect_uri, scope,
                                             state]
        
        clientStoreMock = Mock(spec=ClientStore)
        clientStoreMock.fetch_by_client_id.return_value = {"redirect_uris": [redirect_uri]}
        
        handler = AuthRequestMixin(client_store=clientStoreMock,
                                   site_adapter=Mock(), token_generator=Mock())
        
        result = handler.read_validate_params(request_mock)
        
        request_mock.get_param.assert_has_calls([call("client_id"),
                                                call("redirect_uri"),
                                                call("scope"), call("state")])
        clientStoreMock.fetch_by_client_id.assert_called_with(client_id)
        self.assertEqual(handler.client_id, client_id)
        self.assertEqual(handler.redirect_uri, redirect_uri)
        self.assertEqual(handler.scope, scope)
        self.assertEqual(handler.state, state)
        self.assertTrue(result)
    
    def test_read_validate_params_no_client_id(self):
        request_mock = Mock(spec=Request)
        request_mock.get_param.return_value = None
        
        handler = AuthRequestMixin(client_store=Mock(), site_adapter=Mock(),
                                   token_generator=Mock())
        
        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)
        
        e = expected.exception
        
        request_mock.get_param.assert_called_with("client_id")
        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "Missing client_id parameter")
    
    def test_read_validate_params_invalid_client_id(self):
        client_id = "abc"
        
        request_mock = Mock(spec=Request)
        request_mock.get_param.return_value = client_id
        
        clientStoreMock = Mock(spec=ClientStore)
        clientStoreMock.fetch_by_client_id.return_value = None
        
        handler = AuthRequestMixin(client_store=clientStoreMock,
                                   site_adapter=Mock(), token_generator=Mock())
        
        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)
        
        e = expected.exception
        
        request_mock.get_param.assert_called_with("client_id")
        clientStoreMock.fetch_by_client_id.assert_called_with(client_id)
        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "No client registered")
    
    def test_read_validate_params_invalid_redirect_uri(self):
        client_id = "abc"
        redirect_uri = "http://endpoint-one"
        
        request_mock = Mock(spec=Request)
        request_mock.get_param.side_effect = [client_id, redirect_uri]
        
        clientStoreMock = Mock(spec=ClientStore)
        clientStoreMock.fetch_by_client_id.return_value = {"redirect_uris": ["http://endpoint-two"]}
        
        handler = AuthRequestMixin(client_store=clientStoreMock,
                                   site_adapter=Mock(), token_generator=Mock())
        
        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)
        
        e = expected.exception
        
        request_mock.get_param.assert_has_calls([call("client_id"),
                                                call("redirect_uri")])
        clientStoreMock.fetch_by_client_id.assert_called_with(client_id)
        self.assertEqual(e.error, "invalid_request")
        self.assertEqual(e.explanation, "redirect_uri is not registered for this client")

class AuthorizationCodeAuthHandlerTestCase(unittest.TestCase):
    def test_process(self):
        client_id    = "foobar"
        code         = "abcd"
        environ      = {"session": "data"}
        state        = "mystate"
        redirect_uri = "https://callback"
        user_data    = {"user_id": 789}
        
        location_uri = "%s?state=%s&code=%s" % (redirect_uri, state, code)
        
        auth_token_store_mock = Mock(spec=AuthTokenStore)
        
        response_mock = Mock(spec=Response)
        
        request_mock = Mock(spec=Request)
        
        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.return_value = user_data
        
        token_generator_mock = Mock(spec=["generate"])
        token_generator_mock.generate.return_value = code
        
        handler = AuthorizationCodeAuthHandler(
            auth_token_store=auth_token_store_mock,
            client_store=Mock(), site_adapter=site_adapter_mock,
            token_generator=token_generator_mock
        )
        
        handler.client_id = client_id
        handler.state = state
        handler.redirect_uri = redirect_uri
        response = handler.process(request_mock, response_mock, environ)
        
        token_generator_mock.generate.assert_called_with()
        site_adapter_mock.authenticate.assert_called_with(request_mock,
                                                          environ)
        auth_token_store_mock.save_code.assert_called_with(
            client_id, code, DatetimeMock(1990, 1, 1, 0, 10, 0), redirect_uri,
            user_data
        )
        self.assertEqual(response.status_code, "302 Found")
        self.assertEqual(response.body, "")
        response_mock.add_header.assert_called_with("Location", location_uri)
    
    def test_process_not_confirmed(self):
        environ = {"session": "data"}
        response_mock = Mock(spec=Response)
        
        request_mock = Mock(spec=Request)
        
        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.return_value = None
        site_adapter_mock.render_auth_page.return_value = response_mock
        
        handler = AuthorizationCodeAuthHandler(
            auth_token_store=Mock(), client_store=Mock(),
            site_adapter=site_adapter_mock, token_generator=Mock()
        )
        response = handler.process(request_mock, response_mock, environ)
        
        site_adapter_mock.render_auth_page.assert_called_with(request_mock,
                                                              response_mock,
                                                              environ)
        self.assertEqual(response, response_mock)
    
    def test_redirect_oauth_error(self):
        error_identifier = "eid"
        redirect_uri = "https://callback"
        
        expected_redirect = "%s?error=%s" % (redirect_uri, error_identifier)
        
        error_mock = Mock(spec=OAuthUserError)
        error_mock.error = error_identifier
        
        response_mock = Mock(spec=Response)
        
        handler = AuthorizationCodeAuthHandler(
            auth_token_store=Mock(), client_store=Mock(), site_adapter=Mock(),
            token_generator=Mock()
        )
        handler.redirect_uri = redirect_uri
        result = handler.redirect_oauth_error(error_mock, response_mock)
        
        response_mock.add_header.assert_called_with("Location",
                                                    expected_redirect)
        response_mock.status_code = "302 Found"
        response_mock.body = ""
        self.assertEqual(result, response_mock)

class AuthorizationCodeTokenHandlerTestCase(unittest.TestCase):
    def test_read_validate_params(self):
        client_id = "abc"
        client_secret = "t%gH"
        code = "defg"
        redirect_uri = "http://callback"
        
        auth_token_store_mock = Mock(spec=AuthTokenStore)
        auth_token_store_mock.fetch_by_code.return_value = {
            "code": code,
            "expired_at": DatetimeMock(1990, 1, 1, 0, 0, 0),
            "redirect_uri": redirect_uri
        }
        
        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {
            "redirect_uris": [redirect_uri],
            "secret": client_secret
        }
        
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret, code,
                                               redirect_uri]
        
        handler = AuthorizationCodeTokenHandler(Mock(spec=AccessTokenStore),
                                                auth_token_store_mock,
                                                client_store_mock, Mock())
        result = handler.read_validate_params(request_mock)
        
        request_mock.post_param.assert_has_calls([call("client_id"),
                                                  call("client_secret"),
                                                  call("code"),
                                                  call("redirect_uri")])
        auth_token_store_mock.fetch_by_code.assert_called_with(code)
        self.assertEqual(handler.client_id, client_id)
        self.assertEqual(handler.client_secret, client_secret)
        self.assertEqual(handler.code, code)
        self.assertEqual(handler.redirect_uri, redirect_uri)
        self.assertTrue(result)
    
    def test_read_validate_params_missing_code(self):
        client_id = "abc"
        client_secret = "t%gH"
        code = None
        redirect_uri = "http://callback"
        
        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {
            "secret": client_secret
        }
        
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret, code,
                                               redirect_uri]
        
        handler = AuthorizationCodeTokenHandler(Mock(spec=AccessTokenStore),
                                                Mock(spec=AuthTokenStore),
                                                client_store_mock, Mock())
        
        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)
        
        error = expected.exception
        
        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation,
                         "Missing required parameter in request")
    
    def test_read_validate_params_unknown_code(self):
        client_id     = "abc"
        client_secret = "t%gH"
        code_expected = "defg"
        code_actual   = "xyz"
        redirect_uri  = "http://callback"
        
        auth_token_store_mock = Mock(spec=AuthTokenStore)
        auth_token_store_mock.fetch_by_code.return_value = {
            "code": code_expected
        }
        
        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {
            "redirect_uris": [redirect_uri],
            "secret": client_secret
        }
        
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               code_actual, redirect_uri]
        
        handler = AuthorizationCodeTokenHandler(Mock(spec=AccessTokenStore),
                                                auth_token_store_mock,
                                                client_store_mock, Mock())
        
        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)
        
        error = expected.exception
        
        self.assertEqual(error.error, "invalid_grant")
        self.assertEqual(error.explanation, "Invalid code parameter in request")
    
    def test_read_validate_params_unknown_client(self):
        client_id     = "abc"
        client_secret = "t%gH"
        code   = "xyz"
        redirect_uri  = "http://callback"
        
        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = None
        
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret, code,
                                               redirect_uri]
        
        handler = AuthorizationCodeTokenHandler(Mock(spec=AccessTokenStore),
                                                Mock(spec=AuthTokenStore),
                                                client_store_mock, Mock())
        
        with self.assertRaises(OAuthClientError) as expected:
            handler.read_validate_params(request_mock)
        
        error = expected.exception
        
        self.assertEqual(error.error, "invalid_client")
        self.assertEqual(error.explanation, "Unknown client")
    
    def test_read_validate_params_wrong_client_secret(self):
        client_id     = "abc"
        client_secret_actual = "invalid"
        client_secret_expected = "t%gH"
        code   = "xyz"
        redirect_uri  = "http://callback"
        
        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {
            "secret": client_secret_expected
        }
        
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret_actual,
                                               code, redirect_uri]
        
        handler = AuthorizationCodeTokenHandler(Mock(spec=AccessTokenStore),
                                                Mock(spec=AuthTokenStore),
                                                client_store_mock, Mock())
        
        with self.assertRaises(OAuthClientError) as expected:
            handler.read_validate_params(request_mock)
        
        error = expected.exception
        
        self.assertEqual(error.error, "invalid_client")
        self.assertEqual(error.explanation, "Invalid client_secret")
    
    def test_read_validate_params_wrong_redirect_uri_in_client_data(self):
        client_id     = "abc"
        client_secret = "t%gH"
        code   = "xyz"
        redirect_uri_actual = "http://invalid-callback"
        redirect_uri_expected = "http://callback"
        
        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {
            "redirect_uris": [redirect_uri_expected],
            "secret": client_secret
        }
        
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               code, redirect_uri_actual]
        
        handler = AuthorizationCodeTokenHandler(Mock(spec=AccessTokenStore),
                                                Mock(spec=AuthTokenStore),
                                                client_store_mock, Mock())
        
        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)
        
        error = expected.exception
        
        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation, "Invalid redirect_uri parameter")
    
    def test_read_validate_params_no_auth_code_found(self):
        client_id     = "abc"
        client_secret = "t%gH"
        code   = "xyz"
        redirect_uri = "http://callback"
        
        auth_token_store_mock = Mock(spec=AuthTokenStore)
        auth_token_store_mock.fetch_by_code.return_value = None
        
        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {
            "redirect_uris": [redirect_uri],
            "secret": client_secret
        }
        
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               code, redirect_uri]
        
        handler = AuthorizationCodeTokenHandler(Mock(spec=AccessTokenStore),
                                                auth_token_store_mock,
                                                client_store_mock, Mock())
        
        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)
        
        error = expected.exception
        
        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation,
                         "Invalid authorization code parameter")
    
    def test_read_validate_params_wrong_redirect_uri_in_code_data(self):
        client_id     = "abc"
        client_secret = "t%gH"
        code   = "xyz"
        redirect_uri_actual = "http://invalid-callback"
        redirect_uri_expected = "http://callback"
        
        auth_token_store_mock = Mock(spec=AuthTokenStore)
        auth_token_store_mock.fetch_by_code.return_value = {
            "code": code,
            "redirect_uri": redirect_uri_actual
        }
        
        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {
            "redirect_uris": [redirect_uri_expected],
            "secret": client_secret
        }
        
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               code, redirect_uri_expected]
        
        handler = AuthorizationCodeTokenHandler(Mock(spec=AccessTokenStore),
                                                auth_token_store_mock,
                                                client_store_mock, Mock())
        
        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)
        
        error = expected.exception
        
        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation, "Invalid redirect_uri parameter")
    
    def test_read_validate_params_token_expired(self):
        client_id     = "abc"
        client_secret = "t%gH"
        code   = "xyz"
        redirect_uri = "http://callback"
        token_expired_at = DatetimeMock(1989, 12, 31, 23, 59, 59)
        
        auth_token_store_mock = Mock(spec=AuthTokenStore)
        auth_token_store_mock.fetch_by_code.return_value = {
            "code": code,
            "expired_at": token_expired_at,
            "redirect_uri": redirect_uri
        }
        
        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {
            "redirect_uris": [redirect_uri],
            "secret": client_secret
        }
        
        request_mock = Mock(spec=Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               code, redirect_uri]
        
        handler = AuthorizationCodeTokenHandler(Mock(spec=AccessTokenStore),
                                                auth_token_store_mock,
                                                client_store_mock, Mock())
        
        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)
        
        error = expected.exception
        
        self.assertEqual(error.error, "invalid_grant")
        self.assertEqual(error.explanation, "Authorization code has expired")
    
    def test_process(self):
        access_token = "abcd"
        client_id    = "efg"
        
        expected_body = {"access_token": access_token, "token_type": "Bearer"}
        
        access_token_store_mock = Mock(spec=AccessTokenStore)
        
        token_generator_mock = Mock(spec=["generate"])
        token_generator_mock.generate.return_value = access_token
        
        response_mock = Mock(spec=Response)
        response_mock.body = None
        response_mock.status_code = None
        
        handler = AuthorizationCodeTokenHandler(access_token_store_mock,
                                                Mock(spec=AuthTokenStore),
                                                Mock(spec=ClientStore),
                                                token_generator_mock)
        handler.client_id = client_id
        response = handler.process(Mock(spec=Request), response_mock, {})
        
        access_token_store_mock.save_token.assert_called_with(client_id=client_id,
                                                              token=access_token,
                                                              user_data={})
        self.assertEqual(response.status_code, "200 OK")
        self.assertEqual(response.body, json.dumps(expected_body))
        response_mock.add_header.assert_called_with("Content-type",
                                                    "application/json")
    
    def test_redirect_oauth_error(self):
        error_identifier = "eid"
        expected_content = {"error": error_identifier}
        
        error_mock = Mock(spec=OAuthUserError)
        error_mock.error = error_identifier
        
        response_mock = Mock(spec=Response)
        
        handler = AuthorizationCodeTokenHandler(Mock(), Mock(), Mock(), Mock())
        result = handler.redirect_oauth_error(error_mock, response_mock)
        
        response_mock.add_header.assert_called_with("Content-type",
                                                    "application/json")
        self.assertEqual(response_mock.status_code, "400 Bad Request")
        self.assertEqual(response_mock.body, json.dumps(expected_content))
        self.assertEqual(result, response_mock)

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
        client_id    = "abc"
        environ      = {"session": "data"}
        redirect_uri = "http://callback"
        token        = "tokencode"
        user_id      = 1
        
        access_token_store_mock = Mock(spec=AccessTokenStore)
        
        request_mock = Mock(spec=Request)
        
        responseMock = Mock(spec=Response)
        
        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.return_value = user_id
        
        token_generator_mock = Mock(spec=["generate"])
        token_generator_mock.generate.return_value = token
        
        redirect_uri_with_token = "%s#access_token=%s&token_type=bearer" % (redirect_uri, token)
        
        handler = ImplicitGrantHandler(
            access_token_store=access_token_store_mock, client_store=Mock(),
            site_adapter=site_adapter_mock,
            token_generator=token_generator_mock
        )
        handler.client_id = client_id
        handler.redirect_uri = redirect_uri
        result_response = handler.process(request_mock, responseMock, environ)
        
        site_adapter_mock.authenticate.assert_called_with(request_mock,
                                                          environ)
        access_token_store_mock.save_token.assert_called_with(client_id=client_id,
                                                              token=token,
                                                              user_data=user_id)
        responseMock.add_header.assert_called_with("Location",
                                                   redirect_uri_with_token)
        self.assertEqual(responseMock.status_code, "302 Moved Temporarily")
        self.assertEqual(responseMock.content, "")
        self.assertEqual(result_response, responseMock)
    
    def test_process_unconfirmed(self):
        confirmation_page_result = "confirm"
        environ                  = {"session": "data"}
        
        request_mock = Mock(spec=Request)
        
        responseMock = Mock(spec=Response)
        
        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.authenticate.return_value = None
        site_adapter_mock.render_auth_page.return_value = confirmation_page_result
        
        handler = ImplicitGrantHandler(
            Mock(spec=AccessTokenStore), client_store=Mock(),
            site_adapter=site_adapter_mock, token_generator=Mock()
        )
        result_response = handler.process(request_mock, responseMock, environ)
        
        site_adapter_mock.authenticate.assert_called_with(request_mock,
                                                          environ)
        site_adapter_mock.render_auth_page.assert_called_with(request_mock,
                                                              responseMock,
                                                              environ)
        self.assertEqual(result_response, confirmation_page_result)
    
    def test_process_user_denied_access(self):
        request_mock = Mock(spec=Request)
        
        responseMock = Mock(spec=Response)
        
        site_adapter_mock = Mock(spec=SiteAdapter)
        site_adapter_mock.user_has_denied_access.return_value = True
        
        handler = ImplicitGrantHandler(
            Mock(spec=AccessTokenStore), client_store=Mock(),
            site_adapter=site_adapter_mock, token_generator=Mock()
        )
        
        with self.assertRaises(OAuthUserError) as expected:
            handler.process(request_mock, responseMock, {})
        
        e = expected.exception
        
        site_adapter_mock.user_has_denied_access.assert_called_with(
            request_mock
        )
        self.assertEqual(e.error, "access_denied")
        self.assertEqual(e.explanation, "Authorization denied by user")
    
    def test_redirect_oauth_error(self):
        error_code   = "error_code"
        client_id    = "cid"
        redirect_uri = "https://callback"
        scope        = "scope"
        state        = "state"
        expected_redirect_location = "%s#error=%s" % (redirect_uri, error_code)
        
        client_store_mock = Mock(spec=ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {"redirect_uris": [redirect_uri]}
        
        error_mock = Mock(spec=OAuthUserError)
        error_mock.error = error_code
        
        request_mock = Mock(spec=Request)
        request_mock.get_param.side_effect = [client_id, redirect_uri, scope,
                                             state]
        
        response_mock = Mock(spec=Response)
        
        handler = ImplicitGrantHandler(
            Mock(spec=AccessTokenStore), client_store=client_store_mock,
            site_adapter=Mock(), token_generator=Mock()
        )
        handler.read_validate_params(request_mock)
        altered_response = handler.redirect_oauth_error(error_mock,
                                                        response_mock)
        
        response_mock.add_header.assert_called_with("Location",
                                                    expected_redirect_location)
        self.assertEqual(altered_response.status_code, "302 Moved Temporarily")
        self.assertEqual(altered_response.body, "")

class ResourceOwnerGrantTestCase(unittest.TestCase):
    def test_call(self):
        request_mock = Mock(Request)
        request_mock.post_param.return_value = "password"
        
        access_token_store_mock = Mock(AccessTokenStore)
        client_store_mock = Mock(ClientStore)
        site_adapter_mock = Mock(SiteAdapter)
        token_generator_mock = Mock()
        
        server_mock = Mock(AuthorizationController)
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
        
        server_mock = Mock(AuthorizationController)
        
        factory = ResourceOwnerGrant()
        
        handler = factory(request_mock, server_mock)
        
        request_mock.post_param.assert_called_with("grant_type")
        self.assertEqual(handler, None)

class ResourceOwnerGrantHandlerTestCase(unittest.TestCase):
    def test_process(self):
        access_token = "0aef"
        client_id    = "abcd"
        expected_response_body = {"access_token": access_token,
                                  "token_type": "bearer"}
        user         = {"id": 123}
        
        access_token_store_mock = Mock(AccessTokenStore)
        
        request_mock = Mock(Request)
        
        response_mock = Mock(Response)
        
        site_adapter_mock = Mock(SiteAdapter)
        site_adapter_mock.authenticate.return_value = user
        
        token_generator_mock = Mock()
        token_generator_mock.generate.return_value = access_token
        
        handler = ResourceOwnerGrantHandler(access_token_store_mock,
                                            Mock(ClientStore),
                                            site_adapter_mock,
                                            token_generator_mock)
        handler.client_id = client_id
        result = handler.process(request_mock, response_mock, {})
        
        site_adapter_mock.authenticate.assert_called_with(request_mock, {})
        token_generator_mock.generate.assert_called_with()
        access_token_store_mock.save_token.assert_called_with(client_id,
                                                              access_token,
                                                              user)
        response_mock.add_header.assert_called_with("Content-Type",
                                                    "application/json")
        self.assertEqual(result.status_code, "200 OK")
        self.assertEqual(json.loads(result.body), expected_response_body)
        self.assertEqual(result, response_mock)
    
    def test_read_validate_params(self):
        client_id     = "abcd"
        client_secret = "xyz"
        password      = "johnpw"
        username      = "johndoe"
        
        client_store_mock = Mock(ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {"secret": client_secret}
        
        request_mock = Mock(Request)
        request_mock.post_param.side_effect = [client_id, client_secret,
                                               password, username]
        
        handler = ResourceOwnerGrantHandler(Mock(AccessTokenStore),
                                            client_store_mock,
                                            Mock(SiteAdapter),
                                            Mock())
        result = handler.read_validate_params(request_mock)
        
        client_store_mock.fetch_by_client_id.assert_called_with(client_id)
        self.assertEqual(handler.client_id, client_id)
        self.assertEqual(handler.username, username)
        self.assertEqual(handler.password, password)
        self.assertTrue(result)
    
    def test_read_validate_params_no_client_id(self):
        request_mock = Mock(Request)
        request_mock.post_param.return_value = None
        
        handler = ResourceOwnerGrantHandler(Mock(AccessTokenStore),
                                            Mock(ClientStore),
                                            Mock(SiteAdapter),
                                            Mock())
        
        with self.assertRaises(OAuthInvalidError) as expected:
            handler.read_validate_params(request_mock)
        
        error = expected.exception
        
        request_mock.post_param.assert_called_with("client_id")
        self.assertEqual(error.error, "invalid_request")
        self.assertEqual(error.explanation, "Missing client_id parameter")
    
    def test_read_validate_params_unknown_client_id(self):
        client_id = "abcd"
        
        client_store_mock = Mock(ClientStore)
        client_store_mock.fetch_by_client_id.return_value = None
        
        request_mock = Mock(Request)
        request_mock.post_param.return_value = client_id
        
        handler = ResourceOwnerGrantHandler(Mock(AccessTokenStore),
                                            client_store_mock,
                                            Mock(SiteAdapter),
                                            Mock())
        
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
        
        client_store_mock = Mock(ClientStore)
        client_store_mock.fetch_by_client_id.return_value = {"secret": client_secret_expected}
        
        request_mock = Mock(Request)
        request_mock.post_param.side_effect = [client_id, client_secret_actual]
        
        handler = ResourceOwnerGrantHandler(Mock(AccessTokenStore),
                                            client_store_mock,
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

if __name__ == "__main__":
    unittest.main()
