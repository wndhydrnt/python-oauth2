## 2.0.0 (unreleased)

Features:

  - Pass `data` and `user_id` to the `TokenGenerator` ([@wndhydrnt][])

Improvements:

  - Drop support for Python 2.6 ([@wndhydrnt][])
  - Drop support for Python 3.2 ([@wndhydrnt][])
  - Drop support for Python 3.3 ([@wndhydrnt][])

## 1.0.1

Bugfixes:

  - Fix an error in `ClientCredentialsGrant` when no expiration of a token is set in the handler ([@wndhydrnt][])
  - Fix an error where the body of a POST request would not be parsed if the `Content-Type` header contains a `charset` ([@wndhydrnt][])

## 1.0.0

Features:

  - Logging support ([@wndhydrnt][])
  - Each grant accepts its own site adapter (see [Migration notes](http://python-oauth2.readthedocs.org/en/latest/migration.html)) ([@wndhydrnt][])
  - [Tornado](http://www.tornadoweb.org/) adapter

Improvements:

  - Catch unexpected exceptions and respond with a OAuth2 'server_error' ([@wndhydrnt][])
  - Declare optional dependencies in setup.py ([@wndhydrnt][])
  - Move WSGI server code into its own module ([@wndhydrnt][])
  - Renamed class acting as entrypoint for WSGI server from 'Server' to 'Application' ([@wndhydrnt][])
  - Client Credentials Grant example ([@shupp][])
  - Methods `authenticate` and `render_auth_page` of a Site Adapter accept an instance of `oauth2.datatype.Client` ([@wndhydrnt][])

Bugfixes:

  - Fix Resource Owner Grant responding with HTTP status code '500' in case an owner could not be authorized ([@wndhydrnt][])
  - Fix "scope" parameter not being urlencoded ([@wndhydrnt][])

## 0.7.0

Features:

  - Issue a new refresh token when requesting an access token through the refresh_token grant type ([@jswitzer][])
  - Set the expiration time of a token for each grant individually ([@jswitzer][])
  - Create redis stores ([@bhoomit][])
  - Create mysql stores ([@wndhydrnt][])

Improvements:

  - Update Tornado integration docs ([@kivo360][])
  - Add functional tests for supported storage backends. ([@wndhydrnt][])

Bugfixes:

  - Fix WSGI adapter not passing a list of tuples as headers in Python 3. ([@wndhydrnt][])
  - Fix request for access token responding '400: Bad Request' in Python 3. ([@wndhydrnt][])

## 0.6.0

Features:

  - Issue unique access tokens ([@wndhydrnt][])
  - Define what grants a client is allowed to use ([@wndhydrnt][])

Improvements:

  - Corrected class references in doc strings (@Trii)
  - Proper handling of errors raised by store adapters ([@wndhydrnt][])

Bugfixes:

  - Added missing `scopes` parameter in SiteAdapter base class (@Trii)
  - Deleting authorization token after usage (@Trii)
  - Scope parameter not returned by access token response of Authorization Code Grant ([@wndhydrnt][])
  - Added missing cache control headers to responses containing a token ([@wndhydrnt][])
  - Fixed ClientCredentialsGrant returning a value of 0 of 'expires_in' with refresh token disabled ([@wndhydrnt][])

## 0.5.0

Features:

  - Added Client Credentials Grant ([@wndhydrnt][])
  - Renamed `oauth2.AuthorizationController` to `oauth2.Provider` ([@wndhydrnt][])
  - Added mongodb store ([@wndhydrnt][])

## 0.4.0

Features:

  - Added support for refresh tokens ([@wndhydrnt][])

## 0.3.2

Bugfixes:

  - Fixed a bug where MemcacheTokenStore saved objects instead of dictionaries. ([@wndhydrnt][])

## 0.3.1

Bugfixes:

  - Fixed a bug causing a supplied redirect uri being ignored if it is not the first entry in the list of a client object. ([@wndhydrnt][])

## 0.3.0

Features:

  - Headers of a response are returned as a dictionary ([@wndhydrnt][])
  - Status code of a response is an integer ([@wndhydrnt][])
  - Streamlining the integration of storage classes and site adapters by requiring them to raise specified errors ([@wndhydrnt][])

## 0.2.0

Features:

  - Support for scopes ([@wndhydrnt][])
  - Local token and client stores ([@wndhydrnt][])
  - Memcache token store ([@wndhydrnt][])
  - Support for Python 2.6, 3.2 and 3.3 ([@wndhydrnt][])

## 0.1.0

Features:

  - Working implementation of Authorization Code Grant ([@wndhydrnt][])
  - Working implementation of Implicit Grant ([@wndhydrnt][])
  - Working implementation of Resource Owner Password Credentials Grant ([@wndhydrnt][])

[@wndhydrnt]: https://github.com/wndhydrnt
[@Trii]: https://github.com/Trii
[@jswitzer]: https://github.com/jswitzer
[@kivo360]: https://github.com/kivo360
[@bhoomit]: https://github.com/bhoomit
[@shupp]: https://github.com/shupp
