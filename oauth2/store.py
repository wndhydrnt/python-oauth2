"""
Adapters to persist data during the OAuth 2.0 process.
"""

class AccessTokenStore(object):
    """
    Base class for persisting an access token after it has been generated.
    
    Used by two-legged and three-legged authentication flows.
    """
    def save_token(self, client_id, token, user_data):
        """
        Persists the access token together with the id of the requesting
        client.
        """
        pass

class AuthTokenStore(object):
    """
    Base class for writing and retrieving an auth token during three-legged
    OAuth2 requests.
    """
    def fetch_by_code(self, code):
        """
        Retrieves data of an auth token using its code as identifier.
        """
        pass
    
    def save_code(self, client_id, code, expires_in, redirect_uri, user_data):
        """
        Persists data of an auth token for later use in the request for an
        access token.
        """
        pass

class ClientStore(object):
    """
    Base class for handling OAuth2 clients.
    """
    def fetch_by_client_id(self, client_id):
        """
        Retrieve data of a client by its client identifier.
        """
        pass
