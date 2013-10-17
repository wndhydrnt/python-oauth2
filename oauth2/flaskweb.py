
from flask import request
from oauth2 import AuthorizationController

class Request(object):
    """
    Simple wrapper around the Flask request object
    """
    def get_param(self, name, default=None):
        return request.args.get(key=name, default=default)
    
    def post_param(self, name, default=None):
        return request.form.get(key=name, default=default)

class OAuth2(object):
    """
    Make you Flask application serve OAuth 2.0.
    
    Integrating python-oauth2 in your Flask app is simple::
    
        app = Flask(__name__)
        
        auth_app = OAuth2(access_token_store=token_store,
                  app=app,
                  auth_token_store=token_store,
                  client_store=client_store,
                  site_adapter=TestSiteAdapter(),
                  token_generator=oauth2.tokengenerator.Uuid4())
                  
        auth_app.add_grant(oauth2.grant.AuthorizationCodeGrant())
        auth_app.add_grant(oauth2.grant.ImplicitGrant())
        
        if __name__ == "__main__":
            app.run()
    
    :param access_token_store: Stores access tokens.
                               See ``oauth2.store.AccessTokenStore``.
    :param auth_token_store: Stores and retrieves auth tokens.
                             See ``oauth2.store.AuthTokenStore``.
    :param client_store: Retrieves clients. See ``oauth2.store.ClientStore``.
    :param site_adapter: Contains logic to display messages to the user.
                         See ``oauth2.web.SiteAdapter``.
    :param token_generator: Generates unique tokens.
                            See ``oauth2.tokengenerator``.
    :param app: The Flask application.
    :param authorize_url: The URL where auth tokens can be retrieved
    :param authorize_url: The URL where access tokens can be retrieved
    
    """
    def __init__(self, access_token_store,
                 auth_token_store,
                 client_store,
                 site_adapter,
                 token_generator,
                 app=None,
                 authorize_url="/authorize",
                 token_url="/token"):
        self.access_token_store = access_token_store
        self.auth_token_store   = auth_token_store
        self.client_store       = client_store
        self.site_adapter       = site_adapter
        self.token_generator    = token_generator
        self.authorize_url      = authorize_url
        self.token_url          = token_url
        
        if app is not None:
            self.init_app(app)
        else:
            self.app = None
    
    def add_grant(self, grant):
        """
        Add a grant that your auth server shall support.
        """
        self.controller.add_grant(grant)
    
    def init_app(self, app):
        """
        Initializes view functions.
        """
        self.app = app
        
        self.controller = AuthorizationController(
            access_token_store=self.access_token_store,
            auth_token_store=self.auth_token_store,
            client_store=self.client_store,
            site_adapter=self.site_adapter,
            token_generator=self.token_generator)
        
        self.app.add_url_rule(self.authorize_url, "authorize", self._dispatch,
                              methods=["GET", "POST"])
        self.app.add_url_rule(self.token_url, "token", self._dispatch,
                              methods=["GET", "POST"])
    
    def _dispatch(self):
        if self.controller is None:
            raise
        
        response = self.controller.dispatch(Request(), environ={})
        
        return response.body, response.status_code, response._headers
