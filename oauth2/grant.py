"""
Grants are the heart of OAuth 2.0. Each Grant defines one way for a client to
retrieve an authorization. They are defined in
`Section 4 <http://tools.ietf.org/html/rfc6749#section-4>`_ of the OAuth 2.0
spec.

OAuth 2.0 comes in two flavours of how an access token is issued:
two-legged and three-legged auth. To avoid confusion they are explained in
short here.

Three-legged OAuth
------------------
The "three" symbolizes the parties that are involved:

* The client that wants to access a resource on behalf of the user.
* The user who grants access to her resources.
* The server that issues the access token if the user allows it.

Two-legged OAuth
----------------
The two-legged OAuth process differs from the three-legged process by one
missing participant. The user cannot allow or deny access.

So there are two remaining parties:

* The client that wants to access a resource.
* The server that issues the access.

"""
from oauth2.error import OAuthInvalidError, OAuthUserError, OAuthClientError, \
    ClientNotFoundError, UserNotAuthenticated, AccessTokenNotFound, \
    MissingUserIdentifier
from oauth2.compatibility import urlencode, quote
import json
import time
from oauth2.datatype import AuthorizationCode, AccessToken
from oauth2.web import Response


def encode_scopes(scopes, use_quote=False):
    """
    Creates a string out of a list of scopes.

    :param scopes: A list of scopes
    :param use_quote: Boolean flag indicating whether the string should be quoted
    :return: Scopes as a string
    """
    scopes_as_string = Scope.separator.join(scopes)

    if use_quote:
        return quote(scopes_as_string)
    return scopes_as_string


def json_error_response(error, response):
    """
    Formats an error as a response containing a JSON body.
    """
    msg = {"error": error.error, "description": error.explanation}

    response.status_code = 400
    response.add_header("Content-Type", "application/json")
    response.body = json.dumps(msg)

    return response


def json_success_response(data, response):
    """
    Formats the response of a successful token request as JSON.

    Also adds default headers and status code.
    """
    response.body = json.dumps(data)
    response.status_code = 200

    response.add_header("Content-Type", "application/json")
    response.add_header("Cache-Control", "no-store")
    response.add_header("Pragma", "no-cache")


class Scope(object):
    """
    Handling of the "scope" parameter in a request.

    If ``available`` and ``default`` are both ``None``, the "scope" parameter
    is ignored (the default).

    :param available: A list of strings each defining one supported scope.
    :param default: Value to fall back to in case no scope is present in a
                    request.
    """

    separator = " "

    def __init__(self, available=None, default=None):
        self.scopes = []
        self.send_back = False

        if isinstance(available, list):
            self.available_scopes = available
        else:
            self.available_scopes = []

        self.default = default

    def compare(self, previous_scopes):
        """
        Compares the scopes read from request with previously issued scopes.

        :param previous_scopes: A list of scopes.
        :return: ``True``
        """
        for scope in self.scopes:
            if scope not in previous_scopes:
                raise OAuthInvalidError(
                    error="invalid_scope",
                    explanation="Invalid scope parameter in request")

        return True

    def parse(self, request, source):
        """
        Parses scope value in given request.

        Expects the value of the "scope" parameter in request to be a string
        where each requested scope is separated by a white space::

            # One scope requested
            "profile_read"

            # Multiple scopes
            "profile_read profile_write"

        :param request: An instance of :class:`oauth2.web.Request`.
        :param source: Where to read the scope from. Pass "body" in case of a
                       application/x-www-form-urlencoded body and "query" in
                       case the scope is supplied as a query parameter in the
                       URL of a request.
        """
        if source == "body":
            req_scope = request.post_param("scope")
        elif source == "query":
            req_scope = request.get_param("scope")
        else:
            raise ValueError("Unknown scope source '" + source + "'")

        if req_scope is None:
            if self.default is not None:
                self.scopes = [self.default]
                self.send_back = True
                return
            elif len(self.available_scopes) != 0:
                raise OAuthInvalidError(
                    error="invalid_scope",
                    explanation="Missing scope parameter in request")
            else:
                return

        req_scopes = req_scope.split(self.separator)

        self.scopes = [scope for scope in req_scopes
                       if scope in self.available_scopes]

        if len(self.scopes) == 0 and self.default is not None:
            self.scopes = [self.default]
            self.send_back = True


class ScopeGrant(object):
    """
    Handling of scopes in the OAuth 2.0 flow.

    Inherited by all grants that need to support scopes.

    :param default_scope: The scope identifier that is returned by default.
                          (optional)
    :param scopes:        A list of strings identifying the scopes that the
                          grant supports.
    :param scope_class: The class that does the actual handling in a request.
                        Default: :class:`oauth2.grant.Scope`.
    """

    def __init__(self, default_scope=None, scopes=None, scope_class=Scope,
                 **kwargs):
        self.default_scope = default_scope
        self.scopes = scopes
        self.scope_class = scope_class

        super(ScopeGrant, self).__init__(**kwargs)

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

    This class defines the basic interface of each Grant.
    """

    def __call__(self, request, server):
        raise NotImplementedError


class AuthRequestMixin(object):
    """
    Generalization of reading and validating an incoming request used by
    `oauth2.grant.AuthorizationCodeAuthHandler` and
    `oauth2.grant.ImplicitGrantHandler`.
    """

    def __init__(self, client_store, scope_handler, token_generator,
                 **kwargs):
        self.client_id = None
        self.redirect_uri = None
        self.state = None

        self.client_store = client_store
        self.scope_handler = scope_handler
        self.token_generator = token_generator

        super(AuthRequestMixin, self).__init__(**kwargs)

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

        try:
            client_data = self.client_store.fetch_by_client_id(self.client_id)
        except ClientNotFoundError:
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="No client registered")

        redirect_uri = request.get_param("redirect_uri")

        if redirect_uri is not None:
            if client_data.has_redirect_uri(redirect_uri) == False:
                raise OAuthInvalidError(
                    error="invalid_request",
                    explanation="redirect_uri is not registered for this " \
                                "client")
            else:
                self.redirect_uri = redirect_uri
        else:
            # redirect_uri is an optional param.
            # If not supplied, we use the first entry stored in db as default.
            self.redirect_uri = client_data.redirect_uris[0]

        self.state = request.get_param("state")

        self.scope_handler.parse(request, "query")

        return True


class AuthorizeMixin(object):
    """
    Used by all grants that involve user interaction.
    """

    def __init__(self, site_adapter, **kwargs):
        self.site_adapter = site_adapter

        super(AuthorizeMixin, self).__init__(**kwargs)

    def authorize(self, request, response, environ, scopes):
        """
        Controls all steps to authorize a request by a user.

        :param request: The incoming :class:`oauth2.web.Request`
        :param response: The :class:`oauth2.web.Response` that will be
                         returned eventually
        :param environ: The environment variables of this request
        :param scopes: The scopes requested by an application
        :return: A tuple containing (`dict`, user_id) or the response.

        """
        if self.site_adapter.user_has_denied_access(request) is True:
            raise OAuthUserError(error="access_denied",
                                 explanation="Authorization denied by user")

        try:
            result = self.site_adapter.authenticate(request, environ, scopes)

            return self._sanitize_return_value(result)
        except UserNotAuthenticated:
            return self.site_adapter.render_auth_page(request, response,
                                                      environ, scopes)

    def _sanitize_return_value(self, value):
        if isinstance(value, tuple) and len(value) is 2:
            return value

        return value, None


class AccessTokenMixin(object):
    """
    Used by grants that handle refresh token and unique token.
    """

    def __init__(self, access_token_store, token_generator,
                 unique_token=False, **kwargs):
        self.access_token_store = access_token_store
        self.token_generator = token_generator

        self.unique_token = unique_token

        super(AccessTokenMixin, self).__init__(**kwargs)

    def create_token(self, client_id, data, grant_type, scopes, user_id):
        if self.unique_token:
            if user_id is None:
                raise MissingUserIdentifier

            try:
                access_token = self.access_token_store.\
                    fetch_existing_token_of_user(
                        client_id,
                        grant_type,
                        user_id)

                if (access_token.scopes == scopes
                        and access_token.is_expired() is False):
                    token_data = {"access_token": access_token.token,
                                  "token_type": "Bearer"}

                    if access_token.refresh_token is not None:
                        token_data["refresh_token"] = access_token.refresh_token
                        token_data["expires_in"] = access_token.expires_in

                    return token_data
            except AccessTokenNotFound:
                pass

        token_data = self.token_generator.create_access_token_data()

        access_token = AccessToken(client_id=client_id, data=data,
                                   grant_type=grant_type,
                                   token=token_data["access_token"],
                                   scopes=scopes,
                                   user_id=user_id)

        if "refresh_token" in token_data:
            expires_at = int(time.time()) + token_data["expires_in"]
            access_token.expires_at = expires_at
            access_token.refresh_token = token_data["refresh_token"]

        self.access_token_store.save_token(access_token)

        return token_data


class AuthorizationCodeAuthHandler(AuthorizeMixin, AuthRequestMixin,
                                   GrantHandler):
    """
    Implementation of the first step of the Authorization Code Grant
    (three-legged).
    """

    token_expiration = 600

    def __init__(self, auth_token_store, **kwargs):
        self.auth_code_store = auth_token_store

        super(AuthorizationCodeAuthHandler, self).__init__(**kwargs)

    def process(self, request, response, environ):
        """
        Generates a new authorization token.

        A form to authorize the access of the application can be displayed with
        the help of `oauth2.web.SiteAdapter`.
        """
        data = self.authorize(request, response, environ,
                              self.scope_handler.scopes)

        if isinstance(data, Response):
            return data

        code = self.token_generator.generate()
        expires = int(time.time()) + self.token_expiration

        auth_code = AuthorizationCode(client_id=self.client_id, code=code,
                                      expires_at=expires,
                                      redirect_uri=self.redirect_uri,
                                      scopes=self.scope_handler.scopes,
                                      data=data[0], user_id=data[1])

        self.auth_code_store.save_code(auth_code)

        response.add_header("Location", self._generate_location(code))
        response.body = ""
        response.status_code = 302

        return response

    def redirect_oauth_error(self, error, response):
        """
        Redirects the client in case an error in the auth process occurred.
        """
        query_params = {"error": error.error}

        query = urlencode(query_params)

        location = "%s?%s" % (self.redirect_uri, query)

        response.status_code = 302
        response.body = ""
        response.add_header("Location", location)

        return response

    def _generate_location(self, code):
        query = "code=" + code

        if self.state is not None:
            query += "&state=" + self.state

        return "%s?%s" % (self.redirect_uri, query)


class AuthorizationCodeTokenHandler(AccessTokenMixin, GrantHandler):
    """
    Implementation of the second step of the Authorization Code Grant
    (three-legged).
    """

    def __init__(self, auth_token_store, client_store, **kwargs):
        self.client_id = None
        self.client_secret = None
        self.code = None
        self.data = {}
        self.redirect_uri = None
        self.scopes = []
        self.user_id = None

        self.auth_code_store = auth_token_store
        self.client_store = client_store

        super(AuthorizationCodeTokenHandler, self).__init__(**kwargs)

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
        token_data = self.create_token(
            client_id=self.client_id,
            data=self.data,
            grant_type=AuthorizationCodeGrant.grant_type,
            scopes=self.scopes,
            user_id=self.user_id)

        self.auth_code_store.delete_code(self.code)

        if self.scopes:
            token_data["scope"] = encode_scopes(self.scopes)

        json_success_response(data=token_data, response=response)

        return response

    def redirect_oauth_error(self, error, response):
        return json_error_response(error, response)

    def _read_params(self, request):
        self.client_id = request.post_param("client_id")
        self.client_secret = request.post_param("client_secret")
        self.code = request.post_param("code")
        self.redirect_uri = request.post_param("redirect_uri")

        if (self.code is None
            or self.client_id is None
            or self.client_secret is None
            or self.redirect_uri is None):
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Missing required parameter " \
                                                "in request")

    def _validate_client(self):
        try:
            client = self.client_store.fetch_by_client_id(self.client_id)
        except ClientNotFoundError:
            raise OAuthClientError(error="invalid_client",
                                   explanation="Unknown client")

        if client.secret != self.client_secret:
            raise OAuthClientError(error="invalid_client",
                                   explanation="Invalid client_secret")

        if client.has_redirect_uri(self.redirect_uri) is False:
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Invalid redirect_uri parameter")

    def _validate_code(self):
        stored_code = self.auth_code_store.fetch_by_code(self.code)

        if stored_code is None:
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Invalid authorization code " \
                                                "parameter")

        if stored_code.code != self.code:
            raise OAuthInvalidError(error="invalid_grant",
                                    explanation="Invalid code parameter in " \
                                                "request")

        if stored_code.redirect_uri != self.redirect_uri:
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Invalid redirect_uri parameter")

        if stored_code.is_expired():
            raise OAuthInvalidError(error="invalid_grant",
                                    explanation="Authorization code has expired")

        self.data = stored_code.data
        self.scopes = stored_code.scopes
        self.user_id = stored_code.user_id


class AuthorizationCodeGrant(GrantHandlerFactory, ScopeGrant):
    """
    Implementation of the Authorization Code Grant auth flow.

    This is a three-legged OAuth process.

    Register an instance of this class with
    :class:`oauth2.AuthorizationController` like this::

        auth_controller = AuthorizationController()

        auth_controller.add_grant_type(AuthorizationCodeGrant())
    """

    grant_type = "authorization_code"

    def __init__(self, unique_token=False, **kwargs):
        self.unique_token = unique_token

        super(AuthorizationCodeGrant, self).__init__(**kwargs)

    def __call__(self, request, server):
        if (request.post_param("grant_type") == "authorization_code"
                and request.path == server.token_path):
            return AuthorizationCodeTokenHandler(
                access_token_store=server.access_token_store,
                auth_token_store=server.auth_code_store,
                client_store=server.client_store,
                token_generator=server.token_generator,
                unique_token=self.unique_token)

        if (request.get_param("response_type") == "code"
                and request.path == server.authorize_path):
            scope_handler = self._create_scope_handler()

            return AuthorizationCodeAuthHandler(
                auth_token_store=server.auth_code_store,
                client_store=server.client_store,
                scope_handler=scope_handler,
                site_adapter=server.site_adapter,
                token_generator=server.token_generator)

        return None


class ImplicitGrant(GrantHandlerFactory, ScopeGrant):
    """
    Implementation of the Implicit Grant auth flow.

    This is a three-legged OAuth process.

    Register an instance of this class with
    :class:`oauth2.AuthorizationController` like this::

        auth_controller = AuthorizationController()

        auth_controller.add_grant_type(ImplicitGrant())
    """

    grant_type = "implicit"

    def __call__(self, request, server):
        response_type = request.get_param("response_type")

        if (response_type == "token"
            and request.path == server.authorize_path):
            return ImplicitGrantHandler(
                access_token_store=server.access_token_store,
                client_store=server.client_store,
                scope_handler=self._create_scope_handler(),
                site_adapter=server.site_adapter,
                token_generator=server.token_generator)
        return None


class ImplicitGrantHandler(AuthorizeMixin, AuthRequestMixin, GrantHandler):
    def __init__(self, access_token_store, **kwargs):
        self.access_token_store = access_token_store

        super(ImplicitGrantHandler, self).__init__(**kwargs)

    def process(self, request, response, environ):
        data = self.authorize(request, response, environ,
                              self.scope_handler.scopes)

        if isinstance(data, Response):
            return data

        token = self.token_generator.generate()

        access_token = AccessToken(client_id=self.client_id,
                                   grant_type=ImplicitGrant.grant_type,
                                   token=token, data=data[0],
                                   scopes=self.scope_handler.scopes)

        self.access_token_store.save_token(access_token)

        return self._redirect_access_token(response, token)

    def redirect_oauth_error(self, error, response):
        redirect_location = "%s#error=%s" % (self.redirect_uri, error.error)

        response.add_header("Location", redirect_location)
        response.body = ""
        response.status_code = 302

        return response

    def _redirect_access_token(self, response, token):
        uri_with_fragment = "{0}#access_token={1}&token_type=bearer". \
            format(self.redirect_uri, token)

        if self.state is not None:
            uri_with_fragment += "&state=" + self.state

        if self.scope_handler.send_back is True:
            scopes_as_string = encode_scopes(self.scope_handler.scopes,
                                             use_quote=True)
            uri_with_fragment += "&scope=" + scopes_as_string

        response.status_code = 302
        response.add_header("Location", uri_with_fragment)
        response.content = ""

        return response


class ResourceOwnerGrant(GrantHandlerFactory, ScopeGrant):
    """
    Implementation of the Resource Owner Password Credentials Grant auth flow.

    In this Grant a user provides a user name and a password.
    An access token is issued if the auth server was able to verify the user
    by her credentials.

    Register an instance of this class with
    :class:`oauth2.AuthorizationController` like this::

        auth_controller = AuthorizationController()

        auth_controller.add_grant_type(ResourceOwnerGrant())
    """

    grant_type = "password"

    def __init__(self, unique_token=False, **kwargs):
        self.unique_token = unique_token

        super(ResourceOwnerGrant, self).__init__(**kwargs)

    def __call__(self, request, server):
        """
        Checks if the incoming request can be handled by the
        ResourceOwnerGrantHandler and returns an instance of it.
        """
        if request.post_param("grant_type") != self.grant_type:
            return None

        return ResourceOwnerGrantHandler(
            access_token_store=server.access_token_store,
            client_store=server.client_store,
            scope_handler=self._create_scope_handler(),
            site_adapter=server.site_adapter,
            token_generator=server.token_generator,
            unique_token=self.unique_token)


class ResourceOwnerGrantHandler(GrantHandler, AuthorizeMixin,
                                AccessTokenMixin):
    """
    Class for handling Resource Owner authorization requests.

    See http://tools.ietf.org/html/rfc6749#section-4.3
    """

    def __init__(self, client_store, scope_handler, **kwargs):
        self.client_store = client_store
        self.scope_handler = scope_handler

        self.client_id = None
        self.password = None
        self.username = None

        super(ResourceOwnerGrantHandler, self).__init__(**kwargs)

    def process(self, request, response, environ):
        """
        Takes the incoming request, asks the concrete SiteAdapter to validate
        it and issues a new access token that is returned to the client on
        successful validation.
        """
        data = self.authorize(request=request, response=response,
                              environ=environ,
                              scopes=self.scope_handler.scopes)

        if isinstance(data, Response):
            return data

        token_data = self.create_token(client_id=self.client_id, data=data[0],
                                       grant_type=ResourceOwnerGrant.grant_type,
                                       scopes=self.scope_handler.scopes,
                                       user_id=data[1])

        if self.scope_handler.send_back:
            token_data["scope"] = encode_scopes(self.scope_handler.scopes)

        json_success_response(data=token_data, response=response)

        return response

    def read_validate_params(self, request):
        """
        Checks if all incoming parameters meet the expected values.
        """
        self.client_id = request.post_param("client_id")

        if self.client_id is None:
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Missing client_id parameter")

        try:
            client = self.client_store.fetch_by_client_id(self.client_id)
        except ClientNotFoundError:
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Unknown client")

        if client.secret != request.post_param("client_secret"):
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Could not authenticate client")

        self.password = request.post_param("password")
        self.username = request.post_param("username")

        self.scope_handler.parse(request=request, source="body")

        return True

    def redirect_oauth_error(self, error, response):
        return json_error_response(error, response)


class RefreshToken(GrantHandlerFactory, ScopeGrant):
    """
    Handles requests for refresk tokens as defined in
    http://tools.ietf.org/html/rfc6749#section-6.

    Adding a Refresh Token to the :class:`oauth2.AuthorizationController` like
    this::

        auth_controller = AuthorizationController()

        auth_controller.add_grant_type(RefreshToken(expires_in=600))

    will cause :class:`oauth2.grant.AuthorizationCodeGrant` and
    :class:`oauth2.grant.ResourceOwnerGrant` to include a refresh token and
    expiration in the response.
    """

    grant_type = "refresh_token"

    def __init__(self, expires_in, **kwargs):
        self.expires_in = expires_in

        super(RefreshToken, self).__init__(**kwargs)

    def __call__(self, request, server):
        """
        Determines if the current request requests a refresh token.

        :return: An instance of :class:`RefreshTokenHandler`.
        """
        if request.path != server.token_path:
            return None

        if request.post_param("grant_type") != "refresh_token":
            return None

        return RefreshTokenHandler(
            access_token_store=server.access_token_store,
            client_store=server.client_store,
            scope_handler=self._create_scope_handler(),
            token_generator=server.token_generator)


class RefreshTokenHandler(GrantHandler):
    """
    Validates an incoming request and issues a new access token.
    """

    def __init__(self, access_token_store, client_store, scope_handler,
                 token_generator):
        self.access_token_store = access_token_store
        self.client_store = client_store
        self.scope_handler = scope_handler
        self.token_generator = token_generator

        self.client_id = None
        self.data = {}
        self.refresh_token = None
        self.user_id = None

    def process(self, request, response, environ):
        """
        Create a new access token.

        :param request: The incoming :class:`oauth2.web.Request`.
        :param response: The :class:`oauth2.web.Response` that will be returned
                         to the client.
        :param environ: A ``dict`` containing data of the environment.

        :return: :class:`oauth2.web.Response`

        """

        while True:
            token_data = self.token_generator.create_access_token_data()
            if "refresh_token" not in token_data:
                break
            expires_at = int(time.time()) + token_data["expires_in"]

            access_token = AccessToken(client_id=self.client_id, token=token_data["access_token"],
                                   grant_type=RefreshToken.grant_type,
                                   data=self.data, expires_at=expires_at,
                                   scopes=self.scope_handler.scopes,
                                   user_id=self.user_id)


            access_token.refresh_token = token_data["refresh_token"]

            if self.scope_handler.scopes:
                token_data["scope"] = encode_scope(self.scope_handler.scopes)

            self.access_token_store.save_token(access_token)
            self.access_token_store.delete_refresh_token(self.refresh_token)

            json_success_response(data=token_data, response=response)
            return response


        expires_in = self.token_generator.expires_in
        expires_at = int(time.time()) + expires_in
        token = self.token_generator.generate()

        access_token = AccessToken(client_id=self.client_id, token=token,
                                   grant_type=RefreshToken.grant_type,
                                   data=self.data, expires_at=expires_at,
                                   scopes=self.scope_handler.scopes,
                                   user_id=self.user_id)
        self.access_token_store.save_token(access_token)

        response_data = {"access_token": token, "expires_in": expires_in,
                         "token_type": "Bearer"}

        json_success_response(data=response_data, response=response)

        return response

    def read_validate_params(self, request):
        """
        Validate the incoming request.

        :param request: The incoming :class:`oauth2.web.Request`.

        :return: Returns ``True`` if data is valid.

        :raises: :class:`oauth2.error.OAuthInvalidError`

        """
        self.client_id = request.post_param("client_id")

        if self.client_id is None:
            raise OAuthInvalidError(
                error="invalid_request",
                explanation="Missing client_id in request body")

        client_secret = request.post_param("client_secret")

        if client_secret is None:
            raise OAuthInvalidError(
                error="invalid_request",
                explanation="Missing client_secret in request body")

        self.refresh_token = request.post_param("refresh_token")

        if self.refresh_token is None:
            raise OAuthInvalidError(
                error="invalid_request",
                explanation="Missing refresh_token in request body")

        try:
            client = self.client_store.fetch_by_client_id(self.client_id)

            if client.secret != client_secret:
                raise OAuthInvalidError(error="invalid_request",
                                        explanation="Invalid client secret")
        except ClientNotFoundError:
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Unknown client")

        try:
            access_token = self.access_token_store.fetch_by_refresh_token(
                self.refresh_token
            )
        except AccessTokenNotFound:
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Invalid refresh token")

        refresh_token_expires_at = access_token.expires_at + self.token_generator.expires_in

        if refresh_token_expires_at < int(time.time()):
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Invalid refresh token")

        self.data = access_token.data
        self.user_id = access_token.user_id

        self.scope_handler.parse(request, "body")
        self.scope_handler.compare(access_token.scopes)

        return True

    def redirect_oauth_error(self, error, response):
        return json_error_response(error, response)


class ClientCredentialsGrant(GrantHandlerFactory, ScopeGrant):
    grant_type = "client_credentials"

    def __call__(self, request, server):
        if request.path != server.token_path:
            return None

        if request.post_param("grant_type") == self.grant_type:
            return ClientCredentialsHandler(
                access_token_store=server.access_token_store,
                client_store=server.client_store,
                scope_handler=self._create_scope_handler(),
                token_generator=server.token_generator)
        return None


class ClientCredentialsHandler(GrantHandler):
    def __init__(self, access_token_store, client_store, scope_handler,
                 token_generator):
        self.access_token_store = access_token_store
        self.client_store = client_store
        self.scope_handler = scope_handler
        self.token_generator = token_generator

        self.client_id = None

    def process(self, request, response, environ):
        body = {"token_type": "Bearer"}

        token = self.token_generator.generate()
        expires_at = int(time.time()) + self.token_generator.expires_in

        access_token = AccessToken(client_id=self.client_id,
                                   grant_type=ClientCredentialsGrant.grant_type,
                                   token=token, expires_at=expires_at,
                                   scopes=self.scope_handler.scopes)
        self.access_token_store.save_token(access_token)

        body["access_token"] = token

        if self.token_generator.expires_in > 0:
            body["expires_in"] = self.token_generator.expires_in

        if self.scope_handler.send_back:
            body["scope"] = encode_scopes(self.scope_handler.scopes)

        json_success_response(data=body, response=response)

        return response

    def read_validate_params(self, request):
        self.client_id = request.post_param("client_id")

        if self.client_id is None:
            raise OAuthInvalidError(
                error="invalid_request",
                explanation="Missing client_id in request body")

        client_secret = request.post_param("client_secret")

        if client_secret is None:
            raise OAuthInvalidError(
                error="invalid_request",
                explanation="Missing client_secret in request body")

        try:
            client = self.client_store.fetch_by_client_id(self.client_id)

            if client.secret != client_secret:
                raise OAuthInvalidError(error="invalid_request",
                                        explanation="Invalid client secret")
        except ClientNotFoundError:
            raise OAuthInvalidError(error="invalid_request",
                                    explanation="Unknown client")

        self.scope_handler.parse(request=request, source="body")

    def redirect_oauth_error(self, error, response):
        return json_error_response(error, response)
