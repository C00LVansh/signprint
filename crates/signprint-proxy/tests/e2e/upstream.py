"""Stand-in for the protected app.

Answers every request with the headers it received as JSON, so the e2e
scripts can see what the proxy forwarded. Under /e2e/ it also serves a test
page and the built browser client (pass the client's dist dir as argv[2])."""
import json
import mimetypes
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLIENT_DIST = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else None

PAGE = b"""<!doctype html>
<meta charset="utf-8">
<title>signprint e2e</title>
<script type="module">
  import { SignprintClient } from "/e2e/client/index.js";
  window.SignprintClient = SignprintClient;
  window.clientLoaded = true;
</script>
"""


class Echo(BaseHTTPRequestHandler):
    def _send(self, status, ctype, body):
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _static(self):
        if self.path == "/e2e/index.html":
            return self._send(200, "text/html", PAGE)
        if CLIENT_DIST and self.path.startswith("/e2e/client/"):
            rel = self.path[len("/e2e/client/"):].split("?")[0]
            full = os.path.abspath(os.path.join(CLIENT_DIST, rel))
            if full.startswith(CLIENT_DIST + os.sep) and os.path.isfile(full):
                ctype = "text/javascript" if full.endswith(".js") else (mimetypes.guess_type(full)[0] or "application/octet-stream")
                with open(full, "rb") as f:
                    return self._send(200, ctype, f.read())
        return self._send(404, "text/plain", b"not found")

    def _reply(self):
        if self.command == "GET" and self.path.startswith("/e2e/"):
            return self._static()
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        out = json.dumps({
            "method": self.command,
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "body_len": len(body),
        }).encode()
        self._send(200, "application/json", out)

    do_GET = do_POST = do_PUT = _reply

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Echo).serve_forever()
