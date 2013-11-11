"""
=============
python-oauth2
=============

python-oauth2 is a framework that aims at making it easy to provide
authentication via `OAuth 2.0 <http://tools.ietf.org/html/rfc6749>`_ within
an application stack.

Usage
=====

Example Authorization server::
    
    from wsgiref.simple_server import make_server
    import oauth2
    import oauth2.grant
    import oauth2.error
    import oauth2.store
    import oauth2.tokengenerator
    import oauth2.web

    # Create a SiteAdapter to interact with the user.
    # This can be used to display confirmation dialogs and the like.
    class ExampleSiteAdapter(oauth2.web.SiteAdapter):
        def authenticate(self, request, environ, scopes):
            if request.post_param("confirm") == "1":
                return {}

            raise oauth2.error.UserNotAuthenticated

        def render_auth_page(self, request, response, environ, scopes):
            response.body = '''
    <html>
        <body>
            <form method="POST" name="confirmation_form">
                <input name="confirm" type="hidden" value="1" />
                <input type="submit" value="confirm" />
            </form>
        </body>
    </html>'''
            return response

    # Create an in-memory storage to store your client apps.
    client_store = oauth2.store.LocalClientStore()
    # Add a client
    client_store.add_client(client_id="abc", client_secret="xyz",
                            redirect_uris=["http://localhost/callback"])

    # Create an in-memory storage to store issued tokens.
    # LocalTokenStore can store access and auth tokens
    token_store = oauth2.store.LocalTokenStore()

    # Create the controller.
    auth_controller = oauth2.AuthorizationController(
        access_token_store=token_store,
        auth_code_store=token_store,
        client_store=client_store,
        site_adapter=ExampleSiteAdapter(),
        token_generator=oauth2.tokengenerator.Uuid4()
    )

    # Add Grants you want to support
    auth_controller.add_grant(oauth2.grant.AuthorizationCodeGrant())
    auth_controller.add_grant(oauth2.grant.ImplicitGrant())

    # Wrap the controller with the Wsgi adapter
    app = oauth2.web.Wsgi(server=auth_controller)

    if __name__ == "__main__":
        httpd = make_server('', 8080, app)
        httpd.serve_forever()

Installation
============

python-oauth2 is available on
`PyPI <http://pypi.python.org/pypi/python-oauth2/>`_::
    
    pip install python-oauth2

"""

import json
import time
import urllib
from oauth2.error import OAuthInvalidError, OAuthUserError
from oauth2.web import Request, Response
from oauth2.tokengenerator import Uuid4

VERSION = "0.3.1"

class AccessToken(object):
    """
    An access token and associated data.
    """
    def __init__(self, client_id, token, data={}, scopes=[]):
        self.client_id = client_id
        self.token     = token
        self.data      = data
        self.scopes    = scopes

class AuthorizationCode(object):
    """
    Holds an authorization code and additional information.
    """
    def __init__(self, client_id, code, expires_at, redirect_uri, scopes,
                 data=None):
        self.client_id    = client_id
        self.code         = code
        self.expires_at   = expires_at
        self.redirect_uri = redirect_uri
        self.scopes       = scopes
        self.data         = data
    
    def is_expired(self):
        if self.expires_at < int(time.time()):
            return True
        return False

class Client(object):
    """
    Representation of a client application.
    """
    def __init__(self, identifier, secret, redirect_uris=[]):
        self.identifier    = identifier
        self.secret        = secret
        self.redirect_uris = redirect_uris
    
    def has_redirect_uri(self, uri):
        """
        Checks if a uri is associated with the client.
        """
        return uri in self.redirect_uris

class AuthorizationController(object):
    
    authorize_path = "/authorize"
    token_path = "/token"
    """
    Endpoint of requests to the OAuth 2.0 server.
    
    :param access_token_store: An object that implements methods defiend by
                               :class:`oauth2.store.AccessTokenStore`.
    :param auth_code_store: An object that implements methods defiend by
                            :class:`oauth2.store.AuthTokenStore`.
    :param client_store: An object that implements methods defiend by
                         :class:`oauth2.store.ClientStore`.
    :param site_adapter: An object that implements methods defiend by
                         :class:`oauth2.web.SiteAdapter`.
    :param token_generator: Object to generate unique tokens.
    :param response_class: Class of the response object.
                           Default: :class:`oauth2.web.Response`.
    """
    def __init__(self, access_token_store, auth_code_store, client_store,
                 site_adapter, token_generator, response_class=Response):
        self.grant_types    = []
        self._input_handler = None
        
        self.access_token_store = access_token_store
        self.auth_code_store    = auth_code_store
        self.client_store       = client_store
        self.response_class     = response_class
        self.site_adapter       = site_adapter
        self.token_generator    = token_generator
    
    def add_grant(self, grant):
        """
        Adds a Grant that the server should support.
        """
        self.grant_types.append(grant)
    
    def dispatch(self, request, environ):
        """
        Checks which Grant supports the current request and dispatches to it.
        
        :param request: An instance of :class:`oauth2.web.Request`.
        :param environ: Hash containing variables of the environment.
        
        :return: An instance of ``oauth2.web.Response``.
        """
        try:
            grant_type = self._determine_grant_type(request)
            
            response = self.response_class()
            
            grant_type.read_validate_params(request)
            
            return grant_type.process(request, response, environ)
        except OAuthUserError as error:
            response = self.response_class()
            return grant_type.redirect_oauth_error(error, response)
        except OAuthInvalidError as error:
            response = self.response_class()
            response.add_header("Content-type", "application/json")
            response.status_code = 400
            json_body = {"error": error.error}
            if error.explanation is not None:
                json_body["error_description"] = error.explanation
            
            response.body = json.dumps(json_body)
            return response
    
    def _determine_grant_type(self, request):
        for grant in self.grant_types:
            grant_handler = grant(request, self)
            if grant_handler is not None:
                return grant_handler
        
        raise OAuthInvalidError(error="unsupported_response_type",
                              explanation="Server does not support given " \
                              "response_type")
