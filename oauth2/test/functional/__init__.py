from wsgiref.simple_server import WSGIRequestHandler


class NoLoggingHandler(WSGIRequestHandler):
    """
    Turn off logging access to STDERR in the standard WSGI request handler.
    """
    def log_message(self, format, *args):
        pass
