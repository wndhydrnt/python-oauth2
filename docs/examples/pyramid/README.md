Pyramid integration example for python-oauth2

Integrate the example:

1. Put classes in base.py in appropreate packages. 
2. impl.py contains controller and site adapter. Also place both of them in appropreate packages. 
3. Implement "password_auth" method in OAuth2SiteAdapter.
4. Modify "_get_token_store" and "_get_client_store" methods in UserAuthController
5. Add "config.add_route('authenticateUser', '/user/token')"  to "\__init__\.py"

Add new grant-type:

1. Implement auth method like "password_auth" in OAuth2SiteAdapter.
2. Call "add_grant" on your AuthController


Will add working pyramid project soon. 

