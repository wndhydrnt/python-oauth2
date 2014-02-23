# -*- coding: utf-8 -*-
"""
Definitions of types used by grants.
"""

import time


class AccessToken(object):
    """
    An access token and associated data.
    """
    def __init__(self, client_id, grant_type, token, data={}, expires_at=None,
                 refresh_token=None, scopes=[], user_id=None):
        self.client_id = client_id
        self.grant_type = grant_type
        self.token = token
        self.data = data
        self.expires_at = expires_at
        self.refresh_token = refresh_token
        self.scopes = scopes
        self.user_id = user_id

    @property
    def expires_in(self):
        """
        Returns the time until the token expires.

        :return: The remaining time until expiration in seconds or 0 if the
                 token has expired.
        """
        time_left = self.expires_at - int(time.time())

        if time_left > 0:
            return time_left
        return 0

    def is_expired(self):
        """
        Determines if the token has expired.

        :return: `True` if the token has expired. Otherwise `False`.
        """
        if self.expires_at is None:
            return False

        if self.expires_in > 0:
            return False

        return True

    def to_json(self):
        json = {"access_token": self.token, "token_type": "Bearer"}

        if self.refresh_token is not None:
            json["refresh_token"] = self.refresh_token
            json["expires_in"] = self.expires_in

        return json


class AuthorizationCode(object):
    """
    Holds an authorization code and additional information.
    """
    def __init__(self, client_id, code, expires_at, redirect_uri, scopes,
                 data=None, user_id=None):
        self.client_id = client_id
        self.code = code
        self.data = data
        self.expires_at = expires_at
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.user_id = user_id

    def is_expired(self):
        if self.expires_at < int(time.time()):
            return True
        return False


class Client(object):
    """
    Representation of a client application.
    """
    def __init__(self, identifier, secret, authorized_grants=None,
                 redirect_uris=None):
        self.identifier = identifier
        self.secret = secret

        if authorized_grants is None:
            self.authorized_grants = []
        else:
            self.authorized_grants = authorized_grants

        if redirect_uris is None:
            self.redirect_uris = []
        else:
            self.redirect_uris = redirect_uris

    def has_redirect_uri(self, uri):
        """
        Checks if a uri is associated with the client.

        :param uri: The uri to be checked.

        :return: Boolean
        """
        return uri in self.redirect_uris

    def is_grant_authorized(self, grant_type):
        """
        Checks if the Client is authorized receive tokens for the given grant.

        :param grant_type: The type of the grant.

        :return: Boolean
        """
        return grant_type in self.authorized_grants
