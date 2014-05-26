import json
from multiprocessing import Queue
from multiprocessing.process import Process
from wsgiref.simple_server import make_server
from oauth2 import Provider
from oauth2.grant import AuthorizationCodeGrant, RefreshToken
from oauth2.test import unittest
from oauth2.test.functional import NoLoggingHandler
from oauth2.tokengenerator import Uuid4
from oauth2.web import SiteAdapter, Wsgi
from ..functional import store_factory


try:
    from urllib.request import urlopen
    from urllib.parse import parse_qs, urlencode
    from urllib.error import HTTPError
except ImportError:
    from urllib import urlencode
    from urllib2 import urlopen, HTTPError
    from urlparse import parse_qs


class AuthorizationCodeTestCase(unittest.TestCase):
    def setUp(self):
        self.client = None
        self.provider = None

    def test_request_access_token(self):
        def run_provider(queue):
            try:

                redirect_uri = "http://127.0.0.1:15487/callback"

                stores = store_factory(client_identifier="abc",
                                       client_secret="xyz",
                                       redirect_uris=[redirect_uri])

                provider = Provider(access_token_store=stores["access_token_store"],
                                    auth_code_store=stores["auth_code_store"],
                                    client_store=stores["client_store"],
                                    site_adapter=TestSiteAdapter(),
                                    token_generator=Uuid4())

                provider.add_grant(AuthorizationCodeGrant(expires_in=120))
                provider.add_grant(RefreshToken(expires_in=60))

                app = Wsgi(server=provider)

                httpd = make_server('', 15486, app,
                                    handler_class=NoLoggingHandler)

                queue.put({"result": 0})

                httpd.serve_forever()
            except Exception as e:
                queue.put({"result": 1, "error_message": str(e)})

        def run_client(queue):
            try:
                app = ClientApplication(
                    callback_url="http://127.0.0.1:15487/callback",
                    client_id="abc",
                    client_secret="xyz",
                    provider_url="http://127.0.0.1:15486")

                httpd = make_server('', 15487, app,
                                    handler_class=NoLoggingHandler)

                queue.put({"result": 0})

                httpd.serve_forever()
            except Exception as e:
                queue.put({"result": 1, "error_message": str(e)})

        uuid_regex = "^[a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}-[a-z0-9]{12}$"

        ready_queue = Queue()

        self.provider = Process(target=run_provider, args=(ready_queue,))
        self.provider.start()

        provider_started = ready_queue.get()

        if provider_started["result"] != 0:
            raise Exception("Error starting Provider process with message"
                            "'{0}'".format(provider_started["error_message"]))

        self.client = Process(target=run_client, args=(ready_queue,))
        self.client.start()

        client_started = ready_queue.get()

        if client_started["result"] != 0:
            raise Exception("Error starting Client Application process with "
                            "message '{0}'"
                            .format(client_started["error_message"]))

        access_token_result = urlopen("http://127.0.0.1:15487/app").read()

        access_token_data = json.loads(access_token_result.decode('utf-8'))

        self.assertEqual(access_token_data["token_type"], "Bearer")
        self.assertEqual(access_token_data["expires_in"], 120)
        self.assertRegexpMatches(access_token_data["access_token"],
                                 uuid_regex)
        self.assertRegexpMatches(access_token_data["refresh_token"],
                                 uuid_regex)

        request_data = {"grant_type": "refresh_token",
                        "refresh_token": access_token_data["refresh_token"],
                        "client_id": "abc",
                        "client_secret": "xyz"}

        refresh_token_result = urlopen(
            "http://127.0.0.1:15486/token",
            urlencode(request_data).encode('utf-8')
        )

        refresh_token_data = json.loads(refresh_token_result.read().decode('utf-8'))

        self.assertEqual(refresh_token_data["token_type"], "Bearer")
        self.assertEqual(refresh_token_data["expires_in"], 120)
        self.assertRegexpMatches(refresh_token_data["access_token"],
                                 uuid_regex)

    def tearDown(self):
        if self.client is not None:
            self.client.terminate()
            self.client.join()

        if self.provider is not None:
            self.provider.terminate()
            self.provider.join()


class TestSiteAdapter(SiteAdapter):
    def authenticate(self, request, environ, scopes):
        return {"additional": "data"}, 1

    def user_has_denied_access(self, request):
        return False


class ClientApplication(object):
    def __init__(self, callback_url, client_id, client_secret, provider_url):
        self.callback_url = callback_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_server_url = provider_url

        self.access_token_result = None
        self.auth_token = None
        self.token_type = ""

    def __call__(self, env, start_response):
        try:
            if env["PATH_INFO"] == "/app":
                status, body, headers = self._serve_application()
            elif env["PATH_INFO"] == "/callback":
                status, body, headers = self._read_auth_token(env)
            else:
                status = "301 Moved"
                body = ""
                headers = {"Location": "/app"}
        except HTTPError as http_error:
            print("HTTPError occured:")
            print(http_error.read())
            raise

        start_response(status,
                       [(header, val) for header, val in list(headers.items())])
        return [body]

    def _request_access_token(self):
        post_params = {"client_id": self.client_id,
                       "client_secret": self.client_secret,
                       "code": self.auth_token,
                       "grant_type": "authorization_code",
                       "redirect_uri": self.callback_url}
        token_endpoint = self.api_server_url + "/token"

        result = urlopen(token_endpoint,
                         urlencode(post_params).encode('utf-8'))

        result = json.loads(result.read().decode('utf-8'))
        self.access_token_result = result

        return "302 Found", b"", {"Location": "/app"}

    def _read_auth_token(self, env):
        query_params = parse_qs(env["QUERY_STRING"])
        self.auth_token = query_params["code"][0]

        return "302 Found", b"", {"Location": "/app"}

    def _request_auth_token(self):
        auth_endpoint = self.api_server_url + "/authorize"
        query = urlencode({"client_id": "abc",
                           "redirect_uri": self.callback_url,
                           "response_type": "code"})

        location = "%s?%s" % (auth_endpoint, query)

        return "302 Found", b"", {"Location": location}

    def _serve_application(self):
        if self.access_token_result is None:
            if self.auth_token is None:
                return self._request_auth_token()
            else:
                return self._request_access_token()
        else:
            return ("200 OK",
                    json.dumps(self.access_token_result).encode('utf-8'), {})
