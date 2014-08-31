Tornado
=======


Use Tornado to serve token requests::

    import tornado.web
    import tornado.ioloop

    import oauth2
    import oauth2.error
    from oauth2.tokengenerator import Uuid4
    from oauth2.web import SiteAdapter
    from oauth2.grant import ImplicitGrant
    from oauth2.grant import AuthorizationCodeGrant
    from oauth2.store.memory import ClientStore, AccessTokenStore
    from base import BaseHandler
  
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
      
            # oa = OAuth2Handler("", "")


    def main():
        # Initialize AuthorizationController as usual
        client_store = oauth2.store.memory.ClientStore()
        client_store.add_client(client_id="abc", client_secret="xyz",
                                redirect_uris=["http://localhost:8081/callback"])

        token_store = AccessTokenStore()

        auth_controller = oauth2.Provider(
            access_token_store=token_store,
            auth_code_store=token_store,
            client_store=client_store,
            site_adapter=SiteAdapter(),
            token_generator=oauth2.tokengenerator.Uuid4()
        )

        # Add Grants you want to support
        auth_controller.add_grant(oauth2.grant.AuthorizationCodeGrant())
        auth_controller.add_grant(oauth2.grant.ImplicitGrant())

        # Create your Tornado application and add the handler
        app = tornado.web.Application([
          (r'/authorize', OAuth2Handler, dict(controller=auth_controller))
        ])

        # Start the server
        app.listen(8889)
        print "Server Starting"
        tornado.ioloop.IOLoop.instance().start()

        if __name__ == "__main__":
        main()
        
 
