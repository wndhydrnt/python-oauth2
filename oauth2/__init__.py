"""
Python OAuth 2.0 server
"""

import json
import urllib
from oauth2.error import OAuthInvalidError, OAuthUserError
from oauth2.grant import AuthRequestMixin
from oauth2.web import Request, Response
from oauth2.tokengenerator import Uuid4

VERSION = "0.2.0"

class AuthorizationController(object):
    """
    Endpoint of requests to the OAuth 2.0 server.
    """
    def __init__(self, access_token_store, auth_token_store, client_store,
                 site_adapter, token_generator, response_class=Response):
        self.authorize_path = None
        self.grant_types    = []
        self.token_path     = None
        self._input_handler = None
        
        self.access_token_store = access_token_store
        self.auth_token_store   = auth_token_store
        self.client_store       = client_store
        self.response_class     = response_class
        self.site_adapter       = site_adapter
        self.token_generator    = token_generator
    
    def add_grant(self, grant):
        """
        Adds a Grant that the server should support.
        """
        self.grant_types.append(grant)
    
    def dispatch(self, request, environ):
        """
        Checks which Grant supports the current request and dispatches to it.
        """
        try:
            grant_type = self._determine_grant_type(request)
            
            response = self.response_class()
            
            grant_type.read_validate_params(request)
            
            return grant_type.process(request, response, environ)
        except OAuthUserError, error:
            response = self.response_class()
            return grant_type.redirect_oauth_error(error, response)
        except OAuthInvalidError, error:
            response = self.response_class()
            response.add_header("Content-type", "application/json")
            response.status_code = "400 Bad Request"
            json_body = {"error": error.error}
            if error.explanation is not None:
                json_body["error_description"] = error.explanation
            
            response.body = json.dumps(json_body)
            return response
    
    def _determine_grant_type(self, request):
        for grant in self.grant_types:
            grant_handler = grant(request, self)
            if grant_handler is not None:
                return grant_handler
        
        raise OAuthInvalidError(error="unsupported_response_type",
                              explanation="Server does not support given " \
                              "response_type")
