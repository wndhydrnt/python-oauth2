import json
import os
import signal
import sys
import urllib2

from multiprocessing.process import Process
from wsgiref.simple_server import make_server

sys.path.insert(0, os.path.abspath(os.path.realpath(__file__) + '/../../'))

from oauth2.compatibility import parse_qs, urlencode
from oauth2 import Provider
from oauth2.error import UserNotAuthenticated
from oauth2.store.memory import ClientStore, TokenStore
from oauth2.tokengenerator import Uuid4
from oauth2.web import SiteAdapter, Wsgi
from oauth2.grant import ResourceOwnerGrant


class ClientApplication(object):
    """
    Very basic application that simulates calls to the API of the
    python-oauth2 app.
    """
    client_id = "abc"
    client_secret = "xyz"
    token_endpoint = "http://localhost:8080/token"

    LOGIN_TEMPLATE = """
<html>
    <body>
        <h1>Test Login</h1>
        <form method="POST" name="confirmation_form" action="/request_token">
            <div>
                Username (foo): <input name="username" type="text" />
            </div>
            <div>
                Password (bar): <input name="password" type="password" />
            </div>
            <div>
                <input type="submit" value="submit" />
            </div>
        </form>
    </body>
</html>
    """

    TOKEN_TEMPLATE = """
<html>
    <body>
        <div>Access token: {access_token}</div>
        <div>
            <a href="/reset">Reset</a>
        </div>
    </body>
</html>
    """

    def __init__(self):
        self.token = None
        self.token_type = ""

    def __call__(self, env, start_response):
        if env["PATH_INFO"] == "/login":
            status, body, headers = self._login()
        elif env["PATH_INFO"] == "/":
            status, body, headers = self._display_token()
        elif env["PATH_INFO"] == "/request_token":
            status, body, headers = self._request_token(env)
        elif env["PATH_INFO"] == "/reset":
            status, body, headers = self._reset()
        else:
            status = "301 Moved"
            body = ""
            headers = {"Location": "/"}

        start_response(status,
                       [(header, val) for header,val in headers.iteritems()])
        return body

    def _display_token(self):
        """
        Display token information or redirect to login prompt if none is
        available.
        """
        if self.token is None:
            return "301 Moved", "", {"Location": "/login"}

        return ("200 OK",
                self.TOKEN_TEMPLATE.format(
                    access_token=self.token["access_token"]),
                {})

    def _login(self):
        """
        Login prompt
        """
        return "200 OK", self.LOGIN_TEMPLATE, {}

    def _request_token(self, env):
        """
        Retrieves a new access token from the OAuth2 server.
        """
        params = {}

        content = env['wsgi.input'].read(int(env['CONTENT_LENGTH']))
        post_params = parse_qs(content)
        # Convert to dict for easier access
        for param, value in post_params.items():
            decoded_param = param.decode('utf-8')
            decoded_value = value[0].decode('utf-8')
            if decoded_param == "username" or decoded_param == "password":
                params[decoded_param] = decoded_value

        params["grant_type"] = "password"
        params["client_id"] = self.client_id
        params["client_secret"] = self.client_secret
        # Request an access token by POSTing a request to the auth server.
        response = urllib2.urlopen(self.token_endpoint, urlencode(params))

        self.token = json.load(response)

        return "301 Moved", "", {"Location": "/"}

    def _reset(self):
        self.token = None

        return "302 Found", "", {"Location": "/login"}


class TestSiteAdapter(SiteAdapter):
    def authenticate(self, request, environ, scopes):
        username = request.post_param("username")
        password = request.post_param("password")
        # A real world application could connect to a database, try to
        # retrieve username and password and compare them against the input
        if username == "foo" and password == "bar":
            return

        raise UserNotAuthenticated

    def user_has_denied_access(self, request):
        # In case of Resource Owner Grant a user cannot deny access.
        return False


def run_app_server():
    app = ClientApplication()

    try:
        httpd = make_server('', 8081, app)

        print("Starting Client app on http://localhost:8081/...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


def run_auth_server():
    try:
        client_store = ClientStore()
        client_store.add_client(client_id="abc", client_secret="xyz",
                                redirect_uris=[])

        token_store = TokenStore()

        auth_controller = Provider(
            access_token_store=token_store,
            auth_code_store=token_store,
            client_store=client_store,
            site_adapter=TestSiteAdapter(),
            token_generator=Uuid4())
        auth_controller.add_grant(ResourceOwnerGrant())

        app = Wsgi(server=auth_controller)

        httpd = make_server('', 8080, app)

        print("Starting OAuth2 server on http://localhost:8080/...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


def main():
    auth_server = Process(target=run_auth_server)
    auth_server.start()
    app_server = Process(target=run_app_server)
    app_server.start()
    print("Visit http://localhost:8081/ in your browser")

    def sigint_handler(signal, frame):
        print("Terminating servers...")
        auth_server.terminate()
        auth_server.join()
        app_server.terminate()
        app_server.join()

    signal.signal(signal.SIGINT, sigint_handler)

if __name__ == "__main__":
    main()
