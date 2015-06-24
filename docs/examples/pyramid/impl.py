__author__ = 'Bhoomit'

from pyramid.view import view_config

from oauth2.error import UserNotAuthenticated, UserNotExist
from oauth2.web import SiteAdapter
from oauth2.store.redisdb import TokenStore, ClientStore
from oauth2.grant import ResourceOwnerGrant

from base import BaseAuthController

import os
import sys
import pyramid

class OAuth2SiteAdapter(SiteAdapter):

    def authenticate(self, request, environ, scopes):
        if request.method == "POST":
            if request.post_param("grant_type") == 'password':
                return self.password_auth(request)
        raise UserNotAuthenticated

    def user_has_denied_access(self, request):
        if request.method == "POST":
            if request.post_param("confirm") is "0":
                return True
        return False

    # implement this for resource owner grant 
    def password_auth(self, request):
        session = DBSession()
        try:
        	#validate user credentials  
        	user_id = 123
            if True: 
                return None, user_id
            raise UserNotAuthenticated
        except:
            raise


class UserAuthController(BaseAuthController):

    def __init__(self, request):
        super(UserAuthController, self).__init__(request, OAuth2SiteAdapter())
        self.add_grant(ResourceOwnerGrant(unique_token=True))

    @classmethod
    def _get_token_store(cls):
        settings = get_current_registry().settings
        return TokenStore(
                host = 127.0.0.1,
                port = 6379,
                db = 1,
            )

    @classmethod
    def _get_client_store(cls):
        settings = get_current_registry().settings
        return ClientStore(
                host = 127.0.0.1,
                port = 6379,
                db = 2,
            )

    # add this route in __init__.py
    @view_config(route_name="authenticateUser", renderer="json", request_method="POST")
    def authenticate(self):
        return super(UserAuthController, self).authenticate()

