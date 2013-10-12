"""
OAuth 2.0 Grant types
"""
import datetime
import urllib
from oauth2.error import OAuthInvalidError, OAuthUserError, OAuthClientError
import json

class Scope(object):
    """
    Handler of scopes in the oauth2 flow.
    
    :param available: A list of strings each defining one supported scope
    :param default: Fallback value in case no scope is present in request
    """
    def __init__(self, available=None, default=None):
        self.scopes     = []
        self.send_back  = False
        
        if isinstance(available, list):
            self.available_scopes = available
        else:
            self.available_scopes = []
        
        self.default = default
    
    def parse(self, request):
        """
        Parses scope values from given request.
        
        :param request: ``oauth2.web.Request``
        """
        req_scope = request.get_param("scope")
        
        if req_scope is None:
            if self.default is not None:
                self.scopes = [self.default]
                self.send_back = True
                return
            elif len(self.available_scopes) != 0:
                raise OAuthInvalidError(error="invalid_scope",
                                        explanation="Missing scope parameter in request")
            else:
                return
        
        req_scopes = req_scope.split(" ")
        
        self.scopes = [scope for scope in req_scopes if scope in self.available_scopes]
        
        if len(self.scopes) == 0 and self.default is not None:
            self.scopes = [self.default]
            self.send_back = True

class ScopeGrant(object):
    def __init__(self, default_scope=None, scopes=None, scope_class=Scope):
        self.default_scope = default_scope
        self.scopes        = scopes
        self.scope_class   = scope_class
    
    def _create_scope_handler(self):
        return self.scope_class(available=self.scopes,
                                default=self.default_scope)

class GrantHandler(object):
    """
    Base class every oauth2 handler can extend.
    """
    def process(self, request, response, environ):
        """
        Handles the logic of how a user gets an access token.
        
        This includes steps like calling the implementation of a `SiteAdapter`
        if the user is authorized or generating a new access token.
        
        This method uses data read in `read_validate_params`.
        """
        raise NotImplementedError
    
    def read_validate_params(self, request):
        """
        Reads and validates the incoming data.
        """
        raise NotImplementedError
    
    def redirect_oauth_error(self, error, response):
        """
        Takes all the actions necessary to return an error response in the
        format defined for a specific grant handler.
        """
        raise NotImplementedError

class GrantHandlerFactory(object):
    """
    Base class every handler factory can extend.
    """
    def __call__(self, request, server):
        raise NotImplementedError

class AuthRequestMixin(object):
    """
    Generalization of reading and validating an incoming request used by
    `oauth2.grant.AuthorizationCodeAuthHandler` and
    `oauth2.grant.ImplicitGrantHandler`.
    """
    def __init__(self, client_store, scope_handler, site_adapter,
                 token_generator):
        self.client_id    = None
        self.redirect_uri = None
        self.state        = None
        
        self.client_store    = client_store
        self.scope_handler   = scope_handler
        self.site_adapter    = site_adapter
        self.token_generator = token_generator
    
    def read_validate_params(self, request):
        """
        Reads and validates data in an incoming request as required by
        the Authorization Request of the Authorization Code Grant and the
        Implicit Grant.
        """
        client_id = request.get_param("client_id")
        if client_id is None:
            raise OAuthInvalidError(error="invalid_request",
                                  explanation="Missing client_id parameter")
        self.client_id = client_id
        
        client_data = self.client_store.fetch_by_client_id(self.client_id)
        
        if client_data is None:
            raise OAuthInvalidError(error="invalid_request",
                                  explanation="No client registered")
        
        redirect_uri = request.get_param("redirect_uri")
        
        if (redirect_uri is not None
            and redirect_uri not in client_data["redirect_uris"]):
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="redirect_uri is not registered for this client")
        else:
            self.redirect_uri = client_data["redirect_uris"][0]
        
        self.state = request.get_param("state")
        
        self.scope_handler.parse(request)
        
        return True

class AuthorizationCodeAuthHandler(AuthRequestMixin, GrantHandler):
    """
    Implementation of the first step of the Authorization Code Grant
    (three-legged).
    """
    
    token_expiration = 600
    
    def __init__(self, auth_token_store, client_store, scope_handler,
                 site_adapter, token_generator):
        self.auth_token_store = auth_token_store
        
        AuthRequestMixin.__init__(self, client_store, scope_handler,
                                  site_adapter, token_generator)
    
    def process(self, request, response, environ):
        """
        Generates a new authorization token.
        
        A form to authorize the access of the application can be displayed with
        the help of `oauth2.web.SiteAdapter`.
        """
        user_data = self.site_adapter.authenticate(request, environ)
        
        if user_data is None:
            return self.site_adapter.render_auth_page(request, response,
                                                      environ,
                                                      self.scope_handler.scopes)
        
        code = self.token_generator.generate()
        current_time = datetime.datetime.now()
        expiration_delta = datetime.timedelta(seconds=self.token_expiration)
        expires = current_time + expiration_delta
        self.auth_token_store.save_code(self.client_id, code, expires,
                                        self.redirect_uri,
                                        self.scope_handler.scopes, user_data)
        
        response.add_header("Location", self._generate_location(code))
        response.body = ""
        response.status_code = "302 Found"
        
        return response
    
    def redirect_oauth_error(self, error, response):
        """
        Redirects the client in case an error in the auth process occurred.
        """
        query_params = {"error": error.error}
        
        query = urllib.urlencode(query_params)
        
        location = "%s?%s" % (self.redirect_uri, query)
        
        response.status_code = "302 Found"
        response.body = ""
        response.add_header("Location", location)
        
        return response
    
    def _generate_location(self, code):
        query_params = {"code": code}
        
        if self.state is not None:
            query_params["state"] = self.state
        
        if self.scope_handler.send_back is True:
            query_params["scope"] = " ".join(self.scope_handler.scopes)
        
        query = "&".join([key + "=" + urllib.quote(value) for key,value in query_params.iteritems()])
        
        return "%s?%s" % (self.redirect_uri, query)

class AuthorizationCodeTokenHandler(GrantHandler):
    """
    Implementation of the second step of the Authorization Code Grant
    (three-legged).
    """
    def __init__(self, access_token_store, auth_token_store, client_store,
                 token_generator):
        self.client_id     = None
        self.client_secret = None
        self.code          = None
        self.redirect_uri  = None
        self.scopes        = []
        
        self.access_token_store = access_token_store
        self.auth_token_store   = auth_token_store
        self.client_store       = client_store
        self.token_generator    = token_generator
    
    def read_validate_params(self, request):
        """
        Reads and validates the data from the incoming request.
        
        A valid request is issued via POST consists of the following form-encoded body:
        
        client_id - Identifier of the requesting client (required)
        client_secret - Secret phrase generated by the auth system (required)
        code - Authorization code acquired in the Authorization Request (required)
        redirect_uri - URI that the OAuth2 server should redirect to (optional)
        """
        self._read_params(request)
        
        self._validate_client()
        
        self._validate_code()
        
        return True
    
    def process(self, request, response, environ):
        """
        Generates a new access token and returns it.
        
        Returns the access token and the type of the token as JSON.
        
        Calls `oauth2.store.AccessTokenStore` to persist the token.
        """
        access_token = self.token_generator.generate()
        
        result = {"access_token": access_token, "token_type": "Bearer"}
        
        self.access_token_store.save_token(client_id=self.client_id,
                                           scopes=self.scopes,
                                           token=access_token, user_data={})
        
        response.body = json.dumps(result)
        response.status_code = "200 OK"
        
        response.add_header("Content-type", "application/json")
        
        return response
    
    def redirect_oauth_error(self, error, response):
        """
        Returns a response with status "400" and the error as JSON in case an
        error during the oauth process occurred.
        """
        msg = {"error": error.error}
        
        response.status_code = "400 Bad Request"
        response.add_header("Content-type", "application/json")
        response.body = json.dumps(msg)
        
        return response
    
    def _read_params(self, request):
        self.client_id     = request.post_param("client_id")
        self.client_secret = request.post_param("client_secret")
        self.code          = request.post_param("code")
        self.redirect_uri  = request.post_param("redirect_uri")
        
        if (self.code is None
            or self.client_id is None
            or self.client_secret is None
            or self.redirect_uri is None):
            raise OAuthInvalidError(error="invalid_request",
                                  explanation="Missing required parameter " \
                                              "in request")
    
    def _validate_client(self):
        client = self.client_store.fetch_by_client_id(self.client_id)
        
        if client is None:
            raise OAuthClientError(error="invalid_client",
                                   explanation="Unknown client")
        
        if client["secret"] != self.client_secret:
            raise OAuthClientError(error="invalid_client",
                                   explanation="Invalid client_secret")
        
        if self.redirect_uri not in client["redirect_uris"]:
            raise OAuthInvalidError(error="invalid_request",
                                  explanation="Invalid redirect_uri parameter")
    
    def _validate_code(self):
        stored_code = self.auth_token_store.fetch_by_code(self.code)
        
        if stored_code is None:
            raise OAuthInvalidError(error="invalid_request",
                                  explanation="Invalid authorization code " \
                                              "parameter")
        
        if stored_code["code"] != self.code:
            raise OAuthInvalidError(error="invalid_grant",
                                  explanation="Invalid code parameter in " \
                                              "request")
        
        if stored_code["redirect_uri"] != self.redirect_uri:
            raise OAuthInvalidError(error="invalid_request",
                                  explanation="Invalid redirect_uri parameter")
        
        current_time = datetime.datetime.now()
        if current_time > stored_code["expired_at"]:
            raise OAuthInvalidError(error="invalid_grant",
                                  explanation="Authorization code has expired")
        
        self.scopes = stored_code["scopes"]

class AuthorizationCodeGrant(GrantHandlerFactory, ScopeGrant):
    """
    Implementation of the Authorization Code Grant auth flow also known as
    "three-legged auth".
    
    Register an instance of this class with `oauth2.AuthorizationServer`
    like this::
    
        auth_server = AuthorizationServer()
        
        auth_server.add_grant_type(AuthorizationCodeGrant())
    """
    def __call__(self, request, server):
        if (request.post_param("grant_type") == "authorization_code"
            and request.path == server.token_path):
            return AuthorizationCodeTokenHandler(server.access_token_store,
                                                 server.auth_token_store,
                                                 server.client_store,
                                                 server.token_generator)
        
        if (request.get_param("response_type") == "code"
            and request.path == server.authorize_path):
            scope_handler = self.scope_class(available=self.scopes,
                                             default=self.default_scope)
            
            return AuthorizationCodeAuthHandler(server.auth_token_store,
                                                server.client_store,
                                                scope_handler,
                                                server.site_adapter,
                                                server.token_generator)
        
        return None

class ImplicitGrant(GrantHandlerFactory, ScopeGrant):
    """
    Implementation of the Implicit Grant auth flow also known as
    "two-legged auth".
    
    Register an instance of this class with `oauth2.AuthorizationServer`
    like this::
    
        auth_server = AuthorizationController()
        
        auth_server.add_grant_type(ImplicitGrant())
    """
    def __call__(self, request, server):
        response_type = request.get_param("response_type")
        
        if (response_type == "token"
            and request.path == server.authorize_path):
            scope_handler = self.scope_class(available=self.scopes,
                                             default=self.default_scope)
            
            return ImplicitGrantHandler(
                access_token_store=server.access_token_store,
                client_store=server.client_store, scope_handler=scope_handler,
                site_adapter=server.site_adapter,
                token_generator=server.token_generator)
        return None

class ImplicitGrantHandler(AuthRequestMixin, GrantHandler):
    def __init__(self, access_token_store, client_store, scope_handler,
                 site_adapter, token_generator):
        self.access_token_store = access_token_store
        
        AuthRequestMixin.__init__(self, client_store, scope_handler,
                                  site_adapter, token_generator)
    
    def process(self, request, response, environ):
        if self.site_adapter.user_has_denied_access(request) == True:
            raise OAuthUserError(error="access_denied",
                                 explanation="Authorization denied by user")
        
        user_data = self.site_adapter.authenticate(request, environ)
        
        if user_data is None:
            return self.site_adapter.render_auth_page(request, response,
                                                      environ,
                                                      self.scope_handler.scopes)
        
        token = self.token_generator.generate()
        
        self.access_token_store.save_token(client_id=self.client_id,
                                           scopes=self.scope_handler.scopes,
                                           token=token, user_data=user_data)
        
        return self._redirect_access_token(response, token)
    
    def redirect_oauth_error(self, error, response):
        redirect_location = "%s#error=%s" % (self.redirect_uri, error.error)
        
        response.add_header("Location", redirect_location)
        response.body = ""
        response.status_code = "302 Moved Temporarily"
        
        return response
    
    def _redirect_access_token(self, response, token):
        uri_with_fragment = "%s#access_token=%s&token_type=bearer" % (self.redirect_uri, token)
        
        if self.state is not None:
            uri_with_fragment += "&state=" + self.state
        
        if self.scope_handler.send_back is True:
            uri_with_fragment += "&scope=" + "%20".join(self.scope_handler.scopes)
        
        response.status_code = "302 Moved Temporarily"
        response.add_header("Location", uri_with_fragment)
        response.content = ""
        
        return response

class ResourceOwnerGrant(GrantHandlerFactory, ScopeGrant):
    """
    Factory class to return a ResourceOwnerGrantHandler if the incoming
    request matches the conditions for this type of request.
    """
    def __call__(self, request, server):
        """
        Checks if the incoming request can be handled by the
        ResourceOwnerGrantHandler and returns an instance of it.
        """
        if request.post_param("grant_type") != "password":
            return None
        
        return ResourceOwnerGrantHandler(
            access_token_store=server.access_token_store,
            client_store=server.client_store,
            scope_handler=self._create_scope_handler(),
            site_adapter=server.site_adapter,
            token_generator=server.token_generator)

class ResourceOwnerGrantHandler(GrantHandler):
    """
    Class for handling Resource Owner authorization requests.
    
    See http://tools.ietf.org/html/rfc6749#section-4.3
    """
    def __init__(self, access_token_store, client_store, scope_handler,
                 site_adapter, token_generator):
        self.access_token_store = access_token_store
        self.client_store       = client_store
        self.scope_handler      = scope_handler
        self.site_adapter       = site_adapter
        self.token_generator    = token_generator
        
        self.client_id     = None
        self.password      = None
        self.username      = None
    
    def process(self, request, response, environ):
        """
        Takes the incoming request, asks the concrete SiteAdapter to validate
        it and issues a new access token that is returned to the client on
        successful validation.
        """
        user_data = self.site_adapter.authenticate(request, environ)
        
        access_token = self.token_generator.generate()
        
        self.access_token_store.save_token(self.client_id, access_token,
                                           self.scope_handler.scopes,
                                           user_data)
        
        response_body = {"access_token": access_token, "token_type": "bearer"}
        
        if self.scope_handler.send_back is True:
            response_body["scope"] = " ".join(self.scope_handler.scopes)
        
        response.add_header("Content-Type", "application/json")
        response.status_code = "200 OK"
        response.body = json.dumps(response_body)
        
        return response
    
    def read_validate_params(self, request):
        """
        Checks if all incoming parameters meet the expected values.
        """
        self.client_id = request.post_param("client_id")
        
        if self.client_id is None:
            raise OAuthInvalidError(error="invalid_request",
                                  explanation="Missing client_id parameter")
        
        client = self.client_store.fetch_by_client_id(self.client_id)
        
        if client is None:
            raise OAuthInvalidError(error="invalid_request",
                                  explanation="Unknown client")
        
        if client["secret"] != request.post_param("client_secret"):
            raise OAuthInvalidError(error="invalid_request",
                                  explanation="Could not authenticate client")
        
        self.password = request.post_param("password")
        self.username = request.post_param("username")
        
        self.scope_handler.parse(request=request, source="POST")
        
        return True
    
    def redirect_oauth_error(self, error, response):
        """
        Formats an error as a response containing a JSON body.
        """
        msg = {"error": error.error, "description": error.explanation}
        
        response.status_code = "400 Bad Request"
        response.add_header("Content-Type", "application/json")
        response.body = json.dumps(msg)
        
        return response
