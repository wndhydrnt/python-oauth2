import os
import signal
import sys

from multiprocessing import Process
from wsgiref.simple_server import make_server

sys.path.insert(0, os.path.abspath(os.path.realpath(__file__) + '/../../'))

from oauth2 import AuthorizationController
from oauth2.web import Wsgi, SiteAdapter
from oauth2.tokengenerator import Uuid4
from oauth2.grant import ImplicitGrant
from oauth2.store import AccessTokenStore, AuthTokenStore

class LocalAccessTokenStore(AccessTokenStore):
    def __init__(self):
        self.tokens = {}
    
    def save_token(self, client_id, token, scopes, user_data):
        msg = "Saving token %s for client %s in token store" % (token, client_id)
        print(msg)
        self.tokens[token] = {"client_id": client_id, "scopes": scopes,
                              "user_data": user_data}

class FakeAuthTokenStore(AuthTokenStore):
    pass

class FakeClientStorage(object):
    def fetch_by_client_id(self, client_id):
        # This client storage knows the client with id "abc"
        if client_id == "abc":
            return {"client_id": "abc",
                    "redirect_uris": ["http://localhost:8081/"]}
        return None

class TestSiteAdapter(SiteAdapter):
    CONFIRMATION_TEMPLATE = """
<html>
    <body>
        <form method="POST" name="confirmation_form">
            <input name="confirm" type="hidden" value="1" />
            <div>
                <input type="submit" value="confirm" />
            </div>
        </form>
        <form method="POST" name="confirmation_form">
            <input name="confirm" type="hidden" value="0" />
            <div>
                <input type="submit" value="deny" />
            </div>
        </form>
    </body>
</html>
    """
    
    def render_auth_page(self, request, response, environ, scopes):
        # Add check if the user is logged or a redirect to the login page here
        response.body = self.CONFIRMATION_TEMPLATE
        
        return response
    
    def authenticate(self, request, environ):
        if request.method == "POST":
            if request.post_param("confirm") is "1":
                return True
        return False
    
    def user_has_denied_access(self, request):
        if request.method == "POST":
            if request.post_param("confirm") is "0":
                return True
        return False

def run_app_server():
    def application(env, start_response):
        """
        Serves the local javascript client
        """
        
        js_app = """
<html>
    <head>
        <title>OAuth2 JS Test App</title>
    </head>
    <body>
        <script type="text/javascript">
        var accessToken = null;
        var params = {}
        var hash = window.location.hash.substring(1);
        
        if (hash == "" && accessToken == null) {
            window.location.href = "http://localhost:8080/authorize?response_type=token&client_id=abc&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2F&scope=scope_write"
        }
        
        var hashParts = hash.split("&");
        
        for (var i = 0; i < hashParts.length; i++) {
            var keyValue = hashParts[i].split("=");
            params[keyValue[0]] = keyValue[1]
        }
        
        if ("access_token" in params) {
            alert("Your access token: " + params["access_token"]);
        } else {
            if ("error" in params) {
                if ("access_denied" == params["error"]) {
                    alert("User has denied access");
                } else {
                    alert("An error occured: " + params["error"]);
                }
            }
        }
        </script>
    </body>
</html>
        """
        
        start_response("200 OK", [("Content-Type", "text/html")])
        
        return [js_app]

    try:
        httpd = make_server('', 8081, application)
    
        print("Starting implicit_grant app server on http://localhost:8081/...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


def run_auth_server():
    try:
        auth_server = AuthorizationController(
            access_token_store=LocalAccessTokenStore(),
            auth_token_store=FakeAuthTokenStore(),
            client_store=FakeClientStorage(),
            site_adapter=TestSiteAdapter(),
            token_generator=Uuid4())
        auth_server.add_grant(ImplicitGrant())
        
        app = Wsgi(server=auth_server)
        
        httpd = make_server('', 8080, app)
    
        print("Starting implicit_grant oauth2 server on http://localhost:8080/...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

def main():
    auth_server = Process(target=run_auth_server)
    auth_server.start()
    app_server = Process(target=run_app_server)
    app_server.start()
    print("Access http://localhost:8081/ to start the auth flow")
    
    def sigint_handler(signal, frame):
        print("Terminating servers...")
        auth_server.terminate()
        auth_server.join()
        app_server.terminate()
        app_server.join()
    
    signal.signal(signal.SIGINT, sigint_handler)

if __name__ == "__main__":
    main()
