
import json
from pyramid.response import Response as PyramidResponse
from oauth2.web import Response
from oauth2.error import OAuthInvalidError, \
    ClientNotFoundError, OAuthInvalidNoRedirectError, UnsupportedGrantError, ParameterMissingError
from oauth2.client_authenticator import ClientAuthenticator, request_body
from oauth2.tokengenerator import Uuid4


class Request():
    """
    Contains data of the current HTTP request.
    """
    def __init__(self, env):
        self.method = env.method
        self.params = env.json_body
        self.registry = env.registry
        self.headers = env.registry

    def post_param(self, name):
        return self.params.get(name)


class BaseAuthController(object):

    def __init__(self, request, site_adapter):
        self.request = Request(request)
        self.site_adapter = site_adapter
        self.token_generator = Uuid4()

        self.client_store = self._get_client_store()
        self.access_token_store = self._get_token_store()

        self.client_authenticator = ClientAuthenticator(
                                        client_store=self.client_store,
                                        source=request_body
                                    )

        self.grant_types = [];


    @classmethod
    def _get_token_store(cls):
        NotImplementedError

    @classmethod
    def _get_client_store(cls):
        NotImplementedError

    def add_grant(self, grant):
        """
        Adds a Grant that the provider should support.

        :param grant: An instance of a class that extends
                      :class:`oauth2.grant.GrantHandlerFactory`
        """
        if hasattr(grant, "expires_in"):
            self.token_generator.expires_in[grant.grant_type] = grant.expires_in

        if hasattr(grant, "refresh_expires_in"):
            self.token_generator.refresh_expires_in = grant.refresh_expires_in

        self.grant_types.append(grant)


    def _determine_grant_type(self, request):
        for grant in self.grant_types:
            grant_handler = grant(request, self)
            if grant_handler is not None:
                return grant_handler
        raise UnsupportedGrantError


    def authenticate(self):
        response = Response()
        grant_type = self._determine_grant_type(self.request)
        grant_type.read_validate_params(self.request)
        grant_type.process(self.request, response, {})
        return PyramidResponse(body=response.body, status=response.status_code, content_type="application/json")
