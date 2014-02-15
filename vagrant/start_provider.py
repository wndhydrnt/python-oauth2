from pymongo import MongoClient

from wsgiref.simple_server import make_server

from oauth2 import Provider
from oauth2.store.mongodb import AccessTokenStore, AuthCodeStore, ClientStore
from oauth2.tokengenerator import Uuid4
from oauth2.web import SiteAdapter, Wsgi
from oauth2.grant import AuthorizationCodeGrant, ImplicitGrant, ResourceOwnerGrant,\
    RefreshToken, ClientCredentialsGrant


class TestSiteAdapter(SiteAdapter):
    def authenticate(self, request, environ, response):
        return {}, 123

    def user_has_denied_access(self, request):
        return False


def main():
    client = MongoClient()

    db = client.testdb

    access_token_store = AccessTokenStore(collection=db["access_tokens"])
    auth_code_store = AuthCodeStore(collection=db["auth_codes"])
    client_store = ClientStore(collection=db["clients"])

    provider = Provider(access_token_store=access_token_store,
                        auth_code_store=auth_code_store,
                        client_store=client_store,
                        site_adapter=TestSiteAdapter(),
                        token_generator=Uuid4())

    provider.add_grant(AuthorizationCodeGrant())
    provider.add_grant(ImplicitGrant())
    provider.add_grant(ResourceOwnerGrant())
    provider.add_grant(ClientCredentialsGrant())
    provider.add_grant(RefreshToken(expires_in=600))

    provider.enable_unique_tokens()

    app = Wsgi(server=provider)

    try:
        httpd = make_server('', 8888, app)
        print("Starting test auth server on port 8888...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

if __name__ == "__main__":
    main()
