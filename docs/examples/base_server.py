from wsgiref.simple_server import make_server
import oauth2
import oauth2.grant
import oauth2.error
import oauth2.store.memory
import oauth2.tokengenerator
import oauth2.web.wsgi


# Create a SiteAdapter to interact with the user.
# This can be used to display confirmation dialogs and the like.
class ExampleSiteAdapter(oauth2.web.AuthorizationCodeGrantSiteAdapter,
                         oauth2.web.ImplicitGrantSiteAdapter):
    def authenticate(self, request, environ, scopes, client):
        # Check if the user has granted access
        if request.post_param("confirm") == "confirm":
            return {}

        raise oauth2.error.UserNotAuthenticated

    def render_auth_page(self, request, response, environ, scopes, client):
        response.body = '''
<html>
    <body>
        <form method="POST" name="confirmation_form">
            <input type="submit" name="confirm" value="confirm" />
            <input type="submit" name="deny" value="deny" />
        </form>
    </body>
</html>'''
        return response

    def user_has_denied_access(self, request):
        # Check if the user has denied access
        if request.post_param("deny") == "deny":
            return True
        return False

# Create an in-memory storage to store your client apps.
client_store = oauth2.store.memory.ClientStore()
# Add a client
client_store.add_client(client_id="abc", client_secret="xyz",
                        redirect_uris=["http://localhost/callback"])

site_adapter = ExampleSiteAdapter()

# Create an in-memory storage to store issued tokens.
# LocalTokenStore can store access and auth tokens
token_store = oauth2.store.memory.TokenStore()

# Create the controller.
provider = oauth2.Provider(
    access_token_store=token_store,
    auth_code_store=token_store,
    client_store=client_store,
    token_generator=oauth2.tokengenerator.Uuid4()
)

# Add Grants you want to support
provider.add_grant(oauth2.grant.AuthorizationCodeGrant(site_adapter=site_adapter))
provider.add_grant(oauth2.grant.ImplicitGrant(site_adapter=site_adapter))

# Add refresh token capability and set expiration time of access tokens
# to 30 days
provider.add_grant(oauth2.grant.RefreshToken(expires_in=2592000))

# Wrap the controller with the Wsgi adapter
app = oauth2.web.wsgi.Application(provider=provider)

if __name__ == "__main__":
    httpd = make_server('', 8080, app)
    httpd.serve_forever()
