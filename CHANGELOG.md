## 0.8.0 (unreleased)

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
