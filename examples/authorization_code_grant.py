import os
import sys
import urllib
import urlparse
import json
import signal

from multiprocessing.process import Process
from wsgiref.simple_server import make_server, WSGIRequestHandler

sys.path.insert(0, os.path.abspath(os.path.realpath(__file__) + '/../../'))

from oauth2 import Provider
from oauth2.error import UserNotAuthenticated
from oauth2.store.memory import ClientStore, TokenStore
from oauth2.tokengenerator import Uuid4
from oauth2.web import SiteAdapter, Wsgi
from oauth2.grant import AuthorizationCodeGrant

class ClientRequestHandler(WSGIRequestHandler):
    """
    Request handler that enables formatting of the log messages on the console.

    This handler is used by the client application.
    """
    def address_string(self):
        return "client app"

class OAuthRequestHandler(WSGIRequestHandler):
    """
    Request handler that enables formatting of the log messages on the console.

    This handler is used by the python-oauth2 application.
    """
    def address_string(self):
        return "python-oauth2"

class TestSiteAdapter(SiteAdapter):
    """
    This adapter renders a confirmation page so the user can confirm the auth
    request.
    """

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

class ClientApplication(object):
    """
    Very basic application that simulates calls to the API of the
    python-oauth2 app.
    """
    callback_url   = "http://localhost:8081/callback"
    client_id = "abc"
    client_secret = "xyz"
    api_server_url = "http://localhost:8080"

    def __init__(self):
        self.access_token = None
        self.auth_token   = None
        self.token_type   = ""

    def __call__(self, env, start_response):
        if env["PATH_INFO"] == "/app":
            status, body, headers = self._serve_application()
        elif env["PATH_INFO"] == "/callback":
            status, body, headers = self._read_auth_token(env)
        else:
            status = "301 Moved"
            body = ""
            headers = {"Location": "/app"}

        start_response(status,
                       [(header, val) for header,val in headers.iteritems()])
        return body

    def _request_access_token(self):
        print("Requesting access token...")

        post_params = {"client_id": self.client_id,
                       "client_secret": self.client_secret,
                       "code": self.auth_token,
                       "grant_type": "authorization_code",
                       "redirect_uri": self.callback_url}
        token_endpoint = self.api_server_url + "/token"

        result = urllib.urlopen(token_endpoint,
                                urllib.urlencode(post_params))
        content = ""
        for line in result:
            content += line

        result = json.loads(content)
        self.access_token = result["access_token"]
        self.token_type   = result["token_type"]

        confirmation = "Received access token '%s' of type '%s'" % (self.access_token, self.token_type)
        print(confirmation)
        return "302 Found", "", {"Location": "/app"}

    def _read_auth_token(self, env):
        print("Receiving authorization token...")

        query_params = urlparse.parse_qs(env["QUERY_STRING"])
        self.auth_token = query_params["code"][0]

        print("Received temporary authorization token '%s'" % (self.auth_token,))

        return "302 Found", "", {"Location": "/app"}

    def _request_auth_token(self):
        print("Requesting authorization token...")

        auth_endpoint = self.api_server_url + "/authorize"
        query = urllib.urlencode({"client_id": "abc",
                                  "redirect_uri": self.callback_url,
                                  "response_type": "code"})

        location = "%s?%s" % (auth_endpoint, query)

        return "302 Found", "", {"Location": location}

    def _serve_application(self):
        if self.access_token is None:
            if self.auth_token is None:
                return self._request_auth_token()
            else:
                return self._request_access_token()
        else:
            confirmation = "Current access token '%s' of type '%s'" % (self.access_token, self.token_type)
            return "200 OK", str(confirmation), {}

def run_app_server():
    app = ClientApplication()

    try:
        httpd = make_server('', 8081, app, handler_class=ClientRequestHandler)

        print("Starting Authorization Code Grant client app on http://localhost:8081/...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

def run_auth_server():
    try:
        client_store = ClientStore()
        client_store.add_client(client_id="abc", client_secret="xyz",
                                redirect_uris=["http://localhost:8081/callback"])

        token_store = TokenStore()

        auth_controller = Provider(
            access_token_store=token_store,
            auth_code_store=token_store,
            client_store=client_store,
            site_adapter=TestSiteAdapter(),
            token_generator=Uuid4())
        auth_controller.add_grant(AuthorizationCodeGrant())

        app = Wsgi(server=auth_controller)

        httpd = make_server('', 8080, app, handler_class=OAuthRequestHandler)

        print("Starting implicit_grant oauth2 server on http://localhost:8080/...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

def main():
    auth_server = Process(target=run_auth_server)
    auth_server.start()
    app_server = Process(target=run_app_server)
    app_server.start()
    print("Access http://localhost:8081/app in your browser")

    def sigint_handler(signal, frame):
        print("Terminating servers...")
        auth_server.terminate()
        auth_server.join()
        app_server.terminate()
        app_server.join()

    signal.signal(signal.SIGINT, sigint_handler)

if __name__ == "__main__":
    main()