import os
import signal
import sys

from multiprocessing import Process
from wsgiref.simple_server import make_server

sys.path.insert(0, os.path.abspath(os.path.realpath(__file__) + '/../../'))

from oauth2 import Provider
from oauth2.error import UserNotAuthenticated
from oauth2.web import Wsgi, SiteAdapter
from oauth2.tokengenerator import Uuid4
from oauth2.grant import ImplicitGrant
from oauth2.store.memory import ClientStore, TokenStore

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

    def authenticate(self, request, environ, scopes):
        if request.method == "POST":
            if request.post_param("confirm") == "1":
                return
        raise UserNotAuthenticated

    def user_has_denied_access(self, request):
        if request.method == "POST":
            if request.post_param("confirm") == "0":
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
        client_store = ClientStore()
        client_store.add_client(client_id="abc", client_secret="xyz",
                                redirect_uris=["http://localhost:8081/"])

        token_store = TokenStore()

        auth_server = Provider(
            access_token_store=token_store,
            auth_code_store=token_store,
            client_store=client_store,
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
