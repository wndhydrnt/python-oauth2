"""
Integrating python-oauth2 into Tornado Web Server.
"""
import tornado.web

class Request(object):
    """
    Wraps ``tornado.web.RequestHandler``.
    """
    def __init__(self, request_handler):
        self.request_handler = request_handler
    
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
    Add this handler to your Tornado application.
    
        import oauth2
        import oauth2.tornadoweb
        import tornado.web
        
        # Initialize the AuthorizationController (complete init omitted)
        auth_controller = oauth2.AuthorizationController()
        
        # Create your Tornado application and add the handler
        app = tornado.web.Application([
            (r'/authorize', oauth2.tornadoweb.OAuth2Handler, dict(controller=auth_controller)),
        ])
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
        for name, value in response.headers:
            self.set_header(name, value)
        
        status_code_parts = response.status_code.split(" ")
        
        self.set_status(int(status_code_parts[0]))
        self.write(response.body)
