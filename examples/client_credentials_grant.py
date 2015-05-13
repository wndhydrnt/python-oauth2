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
from oauth2.web import Wsgi
from oauth2.grant import ClientCredentialsGrant

class OAuthRequestHandler(WSGIRequestHandler):
    """
    Request handler that enables formatting of the log messages on the console.

    This handler is used by the python-oauth2 application.
    """
    def address_string(self):
        return "python-oauth2"


def run_auth_server():
    try:
        client_store = ClientStore()
        client_store.add_client(client_id="abc", client_secret="xyz",
                                redirect_uris=[])

        token_store = TokenStore()
        token_gen = Uuid4()
        token_gen.expires_in['client_credentials'] = 3600

        auth_controller = Provider(
            access_token_store=token_store,
            auth_code_store=token_store,
            client_store=client_store,
            token_generator=token_gen)
        auth_controller.add_grant(ClientCredentialsGrant())

        app = Wsgi(server=auth_controller)

        httpd = make_server('', 8080, app, handler_class=OAuthRequestHandler)

        print("Starting implicit_grant oauth2 server on http://localhost:8080/...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

def main():
    auth_server = Process(target=run_auth_server)
    auth_server.start()
    print("To test getting an auth token, execute the following curl command:")
    print(
        "curl --ipv4 -v -X POST"
        " -d 'grant_type=client_credentials&client_id=abc&client_secret=xyz' "
        "http://localhost:8080/token"
    )

    def sigint_handler(signal, frame):
        print("Terminating server...")
        auth_server.terminate()
        auth_server.join()

    signal.signal(signal.SIGINT, sigint_handler)

if __name__ == "__main__":
    main()
