"""
Ensures compatibility between python 2.x and python 3.x
"""

import sys
 
if sys.version_info >= (3, 0):
    from urllib.parse import parse_qs as parse_qs
    from urllib.parse import urlencode as urlencode
    from urllib.parse import quote as quote
else:
    from urlparse import parse_qs as parse_qs
    from urllib import urlencode as urlencode
    from urllib import quote as quote
