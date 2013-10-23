Tornado
=======

Use Tornado to serve token requests::

    import tornado.web
    import tornado.ioloop
    from oauth2.store import LocalClientStore, LocalTokenStore
    from oauth2 import AuthorizationController
    from oauth2.tokengenerator import Uuid4
    from oauth2.web import SiteAdapter
    from oauth2.grant import ImplicitGrant, AuthorizationCodeGrant

    class Request(object):
        """
        Wraps ``tornado.web.RequestHandler``.
        """
        def __init__(self, request_handler):
            self.request_handler = request_handler
            self.path = request_handler.request.path
            
        def get_param(self, name, default=None):
            return self._read_argument(name, default, source="GET")
            
        def post_param(self, name, default=None):
            return self._read_argument(name, default, source="POST")
            
        def _read_argument(self, name, default, source):
            if self.request_handler.request.method != source:
                return None
            try:
                return self.request_handler.get_argument(name)
            except tornado.web.MissingArgumentError:
                return default

    class OAuth2Handler(tornado.web.RequestHandler):
        """
        Dispatches requests to an authorization controller
        """
        def initialize(self, controller):
            self.controller = controller
        
        def get(self):
            response = self._dispatch_request()
            
            self._map_response(response)
        
        def post(self):
            response = self._dispatch_request()
            
            self._map_response(response)
        
        def _dispatch_request(self):
            request = Request(request_handler=self)
            
            return self.controller.dispatch(request, environ={})
        
        def _map_response(self, response):
            for name, value in list(response.headers.items()):
                self.set_header(name, value)
            
            self.set_status(response.status_code)
            self.write(response.body)

    class MySiteAdapter(SiteAdapter):
        def authenticate(self, request, environ, scopes):
            # Authenticate every request
            return {}

    def main():
        # Initialize AuthorizationController as usual
        client_store = LocalClientStore()
        client_store.add_client(client_id="abc", client_secret="xyz",
                                redirect_uris=["http://localhost:8081/callback"])
        
        token_store = LocalTokenStore()
        
        auth_controller = AuthorizationController(
            access_token_store=token_store,
            auth_token_store=token_store,
            client_store=client_store,
            site_adapter=MySiteAdapter(),
            token_generator=Uuid4()
        )
        
        auth_controller.add_grant(AuthorizationCodeGrant())
        auth_controller.add_grant(ImplicitGrant())
        
        # Create your Tornado application and add the handler
        app = tornado.web.Application([
            (r'/authorize', OAuth2Handler, dict(controller=auth_controller))
        ])
        
        # Start the server
        app.listen(8888)
        tornado.ioloop.IOLoop.instance().start()

    if __name__ == "__main__":
        main()