import os
from wsgiref.simple_server import WSGIRequestHandler
from pymongo import MongoClient
import oauth2.store.mongodb
import oauth2.store.memory


class NoLoggingHandler(WSGIRequestHandler):
    """
    Turn off logging access to STDERR in the standard WSGI request handler.
    """
    def log_message(self, format, *args):
        pass


def store_factory(client_identifier, client_secret, redirect_uris):
    stores = {"access_token_store": None, "auth_code_store": None,
              "client_store": None}

    database = os.environ.get("DB")

    if database == "mongodb":
        creator_class = MongoDbStoreCreator
    else:
        creator_class = MemoryStoreCreator

    creator = creator_class(client_identifier, client_secret, redirect_uris)

    creator.initialize()

    creator.before_create()

    stores["access_token_store"] = creator.create_access_token_store()
    stores["auth_code_store"] = creator.create_auth_code_store()
    stores["client_store"] = creator.create_client_store()

    creator.after_create()

    return stores


class StoreCreator(object):
    def __init__(self, client_identifier, client_secret, redirect_uris):
        self.client_identifier = client_identifier
        self.client_secret = client_secret
        self.redirect_uris = redirect_uris

    def initialize(self):
        pass

    def after_create(self):
        pass

    def before_create(self):
        pass

    def create_access_token_store(self):
        raise NotImplementedError

    def create_auth_code_store(self):
        raise NotImplementedError

    def create_client_store(self):
        raise NotImplementedError


class MemoryStoreCreator(StoreCreator):
    def initialize(self):
        self.client_store = oauth2.store.memory.ClientStore()
        self.token_store = oauth2.store.memory.TokenStore()

    def create_access_token_store(self):
        return self.token_store

    def create_auth_code_store(self):
        return self.token_store

    def create_client_store(self):
        return self.client_store

    def after_create(self):
        self.client_store.add_client(client_id=self.client_identifier,
                                     client_secret=self.client_secret,
                                     redirect_uris=self.redirect_uris)


class MongoDbStoreCreator(StoreCreator):
    def initialize(self):
        client = MongoClient('127.0.0.1', 27017)

        self.db = client.test_database

    def create_access_token_store(self):
        return oauth2.store.mongodb.AccessTokenStore(
            collection=self.db["access_tokens"]
        )

    def create_auth_code_store(self):
        return oauth2.store.mongodb.AuthCodeStore(
            collection=self.db["auth_codes"]
        )

    def create_client_store(self):
        return oauth2.store.mongodb.ClientStore(collection=self.db["clients"])

    def after_create(self):
        self.db["clients"].insert({
            "identifier": "abc",
            "secret": "xyz",
            "redirect_uris": ["http://127.0.0.1:15487/callback"]
        })
