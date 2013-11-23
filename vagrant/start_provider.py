from pymongo import MongoClient

from wsgiref.simple_server import make_server

from oauth2 import AuthorizationController, AuthorizationCode, Client
from oauth2.store import AccessTokenStore, AuthCodeStore, ClientStore
from oauth2.error import AuthCodeNotFound, ClientNotFoundError
from oauth2.tokengenerator import Uuid4
from oauth2.web import SiteAdapter, Wsgi
from oauth2.grant import AuthorizationCodeGrant, ImplicitGrant, ResourceOwnerGrant

class MongoDbStore(AccessTokenStore, AuthCodeStore, ClientStore):
    def __init__(self, db):
        self.db = db

    def fetch_by_client_id(self, client_id):
        clients = self.db.clients

        client = clients.find_one({"client_id": client_id})

        if client is None:
            raise ClientNotFoundError

        return Client(client["client_id"], client["client_secret"], client["redirect_uris"])

    def fetch_by_code(self, code):
        auth_codes = self.db.auth_codes

        auth_code = auth_codes.find_one({"code": code})

        if auth_code is None:
            raise AuthCodeNotFound

        return AuthorizationCode(auth_code["client_id"], auth_code["code"],
                                 auth_code["expires_at"], auth_code["redirect_uri"],
                                 auth_code["scopes"])

    def save_code(self, authorization_code):
        auth_codes = self.db.auth_codes

        auth_codes.insert({"client_id": authorization_code.client_id,
                          "code": authorization_code.code,
                          "expires_at": authorization_code.expires_at,
                          "redirect_uri": authorization_code.redirect_uri,
                          "scopes": authorization_code.scopes})

    def save_token(self, access_token):
        access_tokens = self.db.access_tokens

        access_tokens.insert({"client_id": access_token.client_id,
                             "token": access_token.token,
                             "data": access_token.data,
                             "scopes": access_token.scopes})

class TestSiteAdapter(SiteAdapter):
    def authenticate(self, request, environ, response):
        return {}

    def user_has_denied_access(self, request):
        return False

def main():
    client = MongoClient()

    db = client.testdb

    store = MongoDbStore(db=db)

    controller = AuthorizationController(
        access_token_store=store,
        auth_code_store=store,
        client_store=store,
        site_adapter=TestSiteAdapter(),
        token_generator=Uuid4()
    )

    controller.add_grant(AuthorizationCodeGrant())
    controller.add_grant(ImplicitGrant())
    controller.add_grant(ResourceOwnerGrant())

    app = Wsgi(server=controller)

    try:
        httpd = make_server('', 8888, app)
        print("Starting test auth server on port 8888...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

if __name__ == "__main__":
    main()
