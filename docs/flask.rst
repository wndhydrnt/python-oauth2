Flask
=====

Wrapper classes to integrate an OAuth 2.0 Authorization Server into a Flask application::

    from flask import request, Flask
    from oauth2 import AuthorizationController
    from oauth2.store import LocalClientStore, LocalTokenStore
    from oauth2.tokengenerator import Uuid4
    from oauth2.web import SiteAdapter
    from oauth2.grant import AuthorizationCodeGrant

    class Request(object):
        """
        Simple wrapper around the Flask request object
        """
        @property
        def path(self):
            return request.path
        
        def get_param(self, name, default=None):
            return request.args.get(key=name, default=default)
        
        def post_param(self, name, default=None):
            return request.form.get(key=name, default=default)

    class OAuth2(object):
        """
        Extend your Flask application to serve OAuth 2.0.
        """
        def __init__(self, access_token_store,
                     auth_token_store,
                     client_store,
                     site_adapter,
                     token_generator,
                     app=None,
                     authorize_path="/authorize",
                     token_path="/token"):
            self.access_token_store = access_token_store
            self.auth_token_store   = auth_token_store
            self.client_store       = client_store
            self.site_adapter       = site_adapter
            self.token_generator    = token_generator
            self.authorize_path      = authorize_path
            self.token_path          = token_path
            
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
            
            self.controller.authorize_path = self.authorize_path
            self.controller.token_path = self.token_path
            
            self.app.add_url_rule(self.authorize_path, "authorize", self._dispatch,
                                  methods=["GET", "POST"])
            self.app.add_url_rule(self.token_path, "token", self._dispatch,
                                  methods=["GET", "POST"])
        
        def _dispatch(self):
            assert self.controller is not None
            
            response = self.controller.dispatch(Request(), environ={})
            
            return response.body, response.status_code, response.headers

    class MySiteAdapter(SiteAdapter):
        def authenticate(self, request, environ, scopes):
            # Authenticate every request
            return {}

    def main():
        app = Flask(__name__)
        
        # Initialize storage
        client_store = LocalClientStore()
        client_store.add_client(client_id="abc", client_secret="xyz",
                                redirect_uris=["http://localhost:8081/callback"])
        
        token_store = LocalTokenStore()
        
        oauth_app = OAuth2(app=app, access_token_store=token_store,
                           auth_token_store=token_store, client_store=client_store,
                           site_adapter=MySiteAdapter(), token_generator=Uuid4())
        
        oauth_app.add_grant(AuthorizationCodeGrant())
        
        app.run(port=5000, debug=True)

        if __name__ == "__main__":
            main()
