#!/usr/bin/env python

"""
Copyright (c) 2006-2026 sqlmap developers (https://sqlmap.org)
See the file 'LICENSE' for copying permission
"""

from __future__ import print_function

import os
import re
import socket
import threading
import time

try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
except ImportError:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler


class HTTPCallbackHandler(BaseHTTPRequestHandler):
    """
    Handles incoming HTTP callback requests from the target database server,
    used for out-of-band data exfiltration via HTTP.
    """

    server_instance = None

    def do_GET(self):
        if self.server_instance:
            with self.server_instance._lock:
                self.server_instance._requests.append(self.path)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        self.do_GET()

    def log_message(self, format, *args):
        """Suppress default HTTP server logging"""
        pass


class HTTPCallbackServer(object):
    """
    Used for receiving out-of-band HTTP callbacks from target database
    servers, with query results embedded in the URL path.

    Works as an alternative to DNS exfiltration when the target can
    make outbound HTTP requests but DNS tunneling is not available.

    Reference(s):
        Oracle UTL_HTTP.REQUEST()
        Oracle HTTPURITYPE().GETCLOB()
        MSSQL xp_cmdshell + curl/powershell
        PostgreSQL COPY ... TO PROGRAM 'curl ...'
    """

    def __init__(self, port=8080):
        self._requests = []
        self._lock = threading.Lock()
        self._port = port
        self._running = False
        self._initialized = False

        self._server = HTTPServer(("0.0.0.0", port), HTTPCallbackHandler)
        HTTPCallbackHandler.server_instance = self

    def pop(self, prefix=None, suffix=None):
        """
        Returns received HTTP callback request path (if any) that has
        given prefix/suffix combination
        (e.g. /prefix.<query result>.suffix)
        """

        retVal = None

        with self._lock:
            for _ in self._requests:
                if prefix is None and suffix is None:
                    self._requests.remove(_)
                    retVal = _
                    break
                elif prefix and suffix:
                    match = re.search(r"/%s\.(.+?)\.%s" % (re.escape(prefix), re.escape(suffix)), _, re.I)
                    if match:
                        self._requests.remove(_)
                        retVal = match.group(0)
                        break

        return retVal

    def run(self):
        """
        Runs an HTTPCallbackServer instance as a daemon thread
        """

        def _():
            try:
                self._running = True
                self._initialized = True
                self._server.serve_forever()
            except KeyboardInterrupt:
                raise
            finally:
                self._running = False

        thread = threading.Thread(target=_)
        thread.daemon = True
        thread.start()

    def shutdown(self):
        if self._server:
            self._server.shutdown()
        self._running = False


if __name__ == "__main__":
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = None

    try:
        server = HTTPCallbackServer(port=port)
        server.run()
        print("[i] HTTP callback server running on port %d" % port)

        while not server._initialized:
            time.sleep(0.1)

        while server._running:
            while True:
                _ = server.pop()

                if _ is None:
                    break
                else:
                    print("[i] %s" % _)

            time.sleep(1)

    except socket.error as ex:
        if 'Permission' in str(ex):
            print("[x] Please run with sudo/Administrator privileges")
        elif 'Address already in use' in str(ex):
            print("[x] Port %d already in use" % port)
        else:
            raise
    except KeyboardInterrupt:
        os._exit(0)
    finally:
        if server:
            server.shutdown()
