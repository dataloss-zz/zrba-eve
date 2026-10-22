#!/usr/bin/env python3
"""Tiny server so EVE SSO login works (handles token exchange, avoids CORS).

Usage:
  1. In your ESI app set Callback URL to: http://localhost:8080/callback
  2. python3 server.py
  3. Open http://localhost:8080/
"""
import json
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CLIENT_ID = "f6080d22aeda4a90a3f20c5906d83037"
PORT = 8080
ROOT = Path(__file__).parent

class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/exchange":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        data = json.loads(body)
        form = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": data["code"],
            "client_id": CLIENT_ID,
            "code_verifier": data["code_verifier"],
        }).encode()
        req = urllib.request.Request(
            "https://login.eveonline.com/v2/oauth/token",
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                result = resp.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(result)
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def translate_path(self, path):
        clean = path.split("?")[0]
        if clean in ("/", "/index.html", "/callback"):
            return str(ROOT / "index.html")
        return super().translate_path(path)

if __name__ == "__main__":
    print(f"Serving on http://localhost:{PORT}/")
    print(f"Set ESI Callback URL to: http://localhost:{PORT}/callback")
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()
