# -*- coding: utf-8 -*-
import redis
import json

from oauth2.datatype import AccessToken, AuthorizationCode, Client
from oauth2.error import AccessTokenNotFound, AuthCodeNotFound
from oauth2.store import AccessTokenStore, AuthCodeStore, ClientStore

class TokenStore(AccessTokenStore, AuthCodeStore):
    """
    Uses redis to store access tokens and auth tokens.

    This Store supports ``redis``. Arguments are passed to the
    underlying client implementation.

    Initialization::

        import redisdb
        
        token_store = TokenStore(host="127.0.0.1", 
            port=6379, 
            db=0
        )

    """
    def __init__(self, rs=None, prefix="oauth2", *args, **kwargs):
        self.prefix = prefix

        if rs is not None:
            self.rs = rs
        else:
            self.rs = redis.StrictRedis(*args, **kwargs)


    def fetch_by_code(self, code):
        """
        Returns data belonging to an authorization code from redis or
        ``None`` if no data was found.

        See :class:`oauth2.store.AuthCodeStore`.

        """
        code_data = json.loads(self.rs.get(self._generate_cache_key(code)))

        if code_data is None:
            raise AuthCodeNotFound

        return AuthorizationCode(**code_data)

    def save_code(self, authorization_code):
        """
        Stores the data belonging to an authorization code token in redis.

        See :class:`oauth2.store.AuthCodeStore`.

        """
        key = self._generate_cache_key(authorization_code.code)

        self.rs.set(key, json.dumps({"client_id": authorization_code.client_id,
                          "code": authorization_code.code,
                          "expires_at": authorization_code.expires_at,
                          "redirect_uri": authorization_code.redirect_uri,
                          "scopes": authorization_code.scopes,
                          "data": authorization_code.data,
                          "user_id": authorization_code.user_id}))

    def delete_code(self, code):
        """
        Deletes an authorization code after use
        :param code: The authorization code.
        """
        self.rs.delete(self._generate_cache_key(code))

    def save_token(self, access_token):
        """
        Stores the access token and additional data in redis.

        See :class:`oauth2.store.AccessTokenStore`.

        """
        key = self._generate_cache_key(access_token.token)
        self.rs.set(key, access_token.__dict__)

        unique_token_key = self._unique_token_key(access_token.client_id,
                                                  access_token.grant_type,
                                                  access_token.user_id)
        self.rs.set(self._generate_cache_key(unique_token_key),
                    json.dumps(access_token.__dict__))
        self.rs.set("%s:%s"%(access_token.user_id,access_token.client_id), unique_token_key)

        if access_token.refresh_token is not None:
            rft_key = self._generate_cache_key(access_token.refresh_token)
            self.rs.set(rft_key, access_token.__dict__)

    def delete_refresh_token(self, refresh_token):
        """
        Deletes a refresh token after use
        :param refresh_token: The refresh token to delete.
        """
        access_token = self.fetch_by_refresh_token(refresh_token)
        self.rs.delete(self._generate_cache_key(access_token.token))
        self.rs.delete(self._generate_cache_key(refresh_token))

    def fetch_by_refresh_token(self, refresh_token):
        token_data = json.loads(self.rs.get(refresh_token))

        if token_data is None:
            raise AccessTokenNotFound

        return AccessToken(**token_data)

    def fetch_existing_token_of_user(self, client_id, grant_type, user_id):
        data = self.rs.get(self._generate_cache_key(self._unique_token_key(client_id, grant_type,
                                                  user_id)))
        if data is None:
            raise AccessTokenNotFound

        data = json.loads(data)

        return AccessToken(**data)

    def _unique_token_key(self, client_id, grant_type, user_id):
        return "{0}_{1}_{2}".format(client_id, grant_type, user_id)

    def _generate_cache_key(self, identifier):
        return self.prefix + "_" + identifier


class ClientStore(ClientStore):

    def __init__(self, rs=None, *args, **kwargs):
        if rs is not None:
            self.rs = rs
        else:
            self.rs = redis.StrictRedis(*args, **kwargs)

    def add_client(self, client_id, client_secret, redirect_uris,
                   authorized_grants=None, authorized_response_types=None):
        """
        Add a client app.

        :param client_id: Identifier of the client app.
        :param client_secret: Secret the client app uses for authentication
                              against the OAuth 2.0 provider.
        :param redirect_uris: A ``list`` of URIs to redirect to.

        """
        self.rs.set(client_id,json.dumps({
            'identifier':client_id,
            'secret':client_secret,
            'redirect_uris':redirect_uris,
            'authorized_grants':authorized_grants,
            'authorized_response_types':authorized_response_types
            #scopes, user_id
        }))
        return self.fetch_by_client_id(client_id)


    def fetch_by_client_id(self, client_id):
        client_data  = self.rs.get(client_id)

        if client_data is None:
            raise ClientNotFoundError

        client_data = json.loads(client_data)
        
        return Client(
            identifier=client_data['identifier'],
            secret=client_data['secret'],
            redirect_uris=client_data['redirect_uris'],
            authorized_grants=client_data['authorized_grants'],
            authorized_response_types=client_data['authorized_response_types'])
