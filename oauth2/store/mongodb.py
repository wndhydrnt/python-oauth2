from oauth2.store import AccessTokenStore, AuthCodeStore, ClientStore
from oauth2.datatype import AccessToken, AuthorizationCode, Client
from oauth2.error import AccessTokenNotFound, AuthCodeNotFound,\
    ClientNotFoundError

class MongodbStore(object):
    def __init__(self, collection, db):
        self.collection = collection
        self.db = db

class MongodbAccessTokenStore(AccessTokenStore, MongodbStore):
    def fetch_by_refresh_token(self, refresh_token):
        data = self.db[self.collection].\
            find_one({"refresh_token": refresh_token})
        
        if data is None:
            raise AccessTokenNotFound
        
        return AccessToken(client_id=data["client_id"],
                           grant_type=data["grant_type"],
                           token=data["token"],
                           data=data["data"], expires_at=data["expires_at"],
                           refresh_token=data["refresh_token"],
                           scopes=data["scopes"])
    
    def save_token(self, access_token):
        self.db[self.collection].insert({
            "client_id": access_token.client_id,
            "grant_type": access_token.grant_type,
            "token": access_token.token,
            "data": access_token.data,
            "expires_at": access_token.expires_at,
            "refresh_token": access_token.refresh_token,
            "scopes": access_token.scopes})
        
        return True

class MongodbAuthCodeStore(AuthCodeStore, MongodbStore):
    def fetch_by_code(self, code):
        code_data = self.db[self.collection].find_one({"code": code})
        
        if code_data is None:
            raise AuthCodeNotFound
        
        return AuthorizationCode(client_id=code_data["client_id"],
                                 code=code_data["code"],
                                 expires_at=code_data["expires_at"],
                                 redirect_uri=code_data["redirect_uri"],
                                 scopes=code_data["scopes"],
                                 data=code_data["data"])
    
    def save_code(self, authorization_code):
        self.db[self.collection].insert({
            "client_id": authorization_code.client_id,
            "code": authorization_code.code,
            "expires_at": authorization_code.expires_at,
            "redirect_uri": authorization_code.redirect_uri,
            "scopes": authorization_code.scopes,
            "data": authorization_code.data})
        
        return True

class MongodbClientStore(ClientStore, MongodbStore):
    def fetch_by_client_id(self, client_id):
        client_data = self.db[self.collection].find_one(
            {"identifier": client_id})
        
        if client_data is None:
            raise ClientNotFoundError
        
        return Client(identifier=client_data["identifier"],
                      secret=client_data["secret"],
                      redirect_uris=client_data["redirect_uris"])
