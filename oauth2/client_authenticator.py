import basicauth
from basicauth import DecodeError
from oauth2.error import OAuthInvalidNoRedirectError, RedirectUriUnknown, \
    OAuthInvalidError, ClientNotFoundError


class ClientAuthenticator(object):
    def __init__(self, client_store, source=None):
        """
        Constructor.

        :param client_store: An instance of :class:`oauth2.store.ClientStore`.
        :param source: A callable that returns a tuple
                       (<client_id>, <client_secret>). Defaults to
                       `oauth2.client_authenticator.request_body_source`.
        """
        self.client_store = client_store
        self.source = source

        if self.source is None:
            self.source = request_body

    def by_identifier(self, request):
        """
        Authenticates a client by its identifier.

        :param request: An instance of :class:`oauth2.web.Request`.

        :return: An instance of :class:`oauth2.datatype.Client`.
        :raises: :class OAuthInvalidNoRedirectError:
        """
        client_id = request.get_param("client_id")

        if client_id is None:
            raise OAuthInvalidNoRedirectError(error="missing_client_id")

        try:
            client = self.client_store.fetch_by_client_id(client_id)
        except ClientNotFoundError:
            raise OAuthInvalidNoRedirectError(error="unknown_client")

        redirect_uri = request.get_param("redirect_uri")
        if redirect_uri is not None:
            try:
                client.redirect_uri = redirect_uri
            except RedirectUriUnknown:
                raise OAuthInvalidNoRedirectError(
                    error="invalid_redirect_uri")

        return client

    def by_identifier_secret(self, request):
        """
        Authenticates a client by its identifier and secret (aka password).

        :param request: An instance of :class:`oauth2.web.Request`.

        :return: An instance of :class:`oauth2.datatype.Client`.
        """
        client_id, client_secret = self.source(request=request)

        try:
            client = self.client_store.fetch_by_client_id(client_id)
        except ClientNotFoundError:
            raise OAuthInvalidError(error="invalid_client",
                                    explanation="No client found")

        grant_type = request.post_param("grant_type")
        if client.grant_type_supported(grant_type) is False:
            raise OAuthInvalidError(error="unauthorized_client",
                                    explanation="Grant type not allowed")

        if client.secret != client_secret:
            raise OAuthInvalidError(error="invalid_client",
                                    explanation="Invalid client credentials")

        return client


def request_body(request):
    """
    Extracts the credentials of a client from the body of a request.

    :param request: An instance of :class:`oauth2.web.Request`

    :return: A tuple of the format `(<CLIENT ID>, <CLIENT SECRET>)`
    """
    client_id = request.post_param("client_id")
    if client_id is None:
        raise OAuthInvalidError(error="invalid_request",
                                explanation="Missing client identifier")

    client_secret = request.post_param("client_secret")
    if client_secret is None:
        raise OAuthInvalidError(error="invalid_request",
                                explanation="Missing client credentials")

    return client_id, client_secret


def http_basic_auth(request):
    """
    Extracts the credentials of a client using HTTP Basic Auth.

    :param request: An instance of :class:`oauth2.web.Request`

    :return: A tuple of the format `(<CLIENT ID>, <CLIENT SECRET>)`
    """
    auth_header = request.header("authorization")

    if auth_header is None:
        raise OAuthInvalidError(error="invalid_request",
                                explanation="Missing authorization header")

    try:
        return basicauth.decode(auth_header)
    except DecodeError:
        raise OAuthInvalidError(
            error="invalid_request",
            explanation="Invalid value of authorization header")
