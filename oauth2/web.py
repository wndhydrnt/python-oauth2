from oauth2.compatibility import parse_qs

class SiteAdapter(object):
    """
    Base class 
    """
    def render_auth_page(self, request, response, environ):
        pass
    
    def authenticate(self, request, environ, scopes):
        pass
    
    def user_has_denied_access(self, request):
        pass

class Request(object):
    def __init__(self, env):
        self.method       = env["REQUEST_METHOD"]
        self.query_params = {}
        self.query_string = env["QUERY_STRING"]
        self.path         = env["PATH_INFO"]
        self.post_params  = {}
        
        for param,value in parse_qs(env["QUERY_STRING"]).items():
            self.query_params[param] = value[0]
        
        if (self.method == "POST"
            and env["CONTENT_TYPE"] == "application/x-www-form-urlencoded"):
            self.post_params = {}
            content = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
            post_params = parse_qs(content)
            
            for param,value in post_params.items():
                self.post_params[param] = value[0]
    
    def get_param(self, name, default=None):
        try:
            return self.query_params[name]
        except KeyError:
            return default
    
    def post_param(self, name, default=None):
        try:
            return self.post_params[name]
        except KeyError:
            return default

class Response(object):
    def __init__(self):
        self.status_code = "200 OK"
        self._headers    = {"Content-type": "text/html"}
        self.body        = ""
    
    @property
    def headers(self):
        return self._headers.items()
    
    def add_header(self, header, value):
        self._headers[header] = str(value)

class Wsgi(object):
    def __init__(self, server, authorize_uri="/authorize", env_vars=None,
                 request_class=Request, token_uri="/token"):
        self.authorize_uri = authorize_uri
        self.env_vars      = env_vars
        self.request_class = request_class
        self.server        = server
        self.token_uri     = token_uri
        
        self.server.authorize_path = authorize_uri
        self.server.token_path     = token_uri
    
    def __call__(self, env, start_response):
        environ = {}
        
        if (env["PATH_INFO"] != self.authorize_uri
            and env["PATH_INFO"] != self.token_uri):
            start_response("500 Internal Wsgi Error",
                           [('Content-type', 'text/html')])
            return ["Internal Wsgi Error"]
        
        request = self.request_class(env)
        
        if isinstance(self.env_vars, list):
            for varname in self.env_vars:
                if varname in env:
                    environ[varname] = env[varname]
        
        response = self.server.dispatch(request, environ)
        
        start_response(response.status_code, response.headers)
        
        return [response.body]
