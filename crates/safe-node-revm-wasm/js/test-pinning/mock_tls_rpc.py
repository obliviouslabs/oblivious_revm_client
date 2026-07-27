#!/usr/bin/env python3
import json
import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_json(200, {"status": "ok"})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        try:
            length = int(self.headers.get("content-length", "0"))
            if length > 1024 * 1024:
                raise ValueError("request exceeds 1 MiB")
            request = json.loads(self.rfile.read(length))
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "mock": True,
                    "method": request.get("method"),
                },
            }
            self.send_json(200, response)
        except Exception as error:
            self.send_json(400, {"error": str(error)})

    def send_json(self, status, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


def main():
    port = int(os.environ.get("MOCK_PORT", "8443"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certs/server-cert.pem", "/certs/server-key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
