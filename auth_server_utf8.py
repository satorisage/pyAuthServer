#!/usr/bin/env python3

import http.server
import socketserver
import base64
import os
import sys
import hashlib
import argparse
import threading
import time
import traceback
from urllib.parse import unquote
from dotenv import load_dotenv, set_key
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from getpass import getpass

ENV_PATH = ".env"

# Load .env file
load_dotenv(ENV_PATH)

USERNAME = os.environ.get("AUTH_USERNAME", "admin")
PASSWORD_HASH = os.environ.get("AUTH_PASSWORD_HASH", "")
DEFAULT_PORT = int(os.environ.get("AUTH_PORT", "80"))
DEFAULT_PUBLIC_DIR = os.environ.get("AUTH_PUBLIC_DIR", "public")
DEFAULT_SERVE_DIR = os.environ.get("AUTH_SERVE_DIR", ".")
DEFAULT_PUBLIC_REDIRECT = os.environ.get("AUTH_PUBLIC_REDIRECT")
TRANSFER_METHOD = os.environ.get("TRANSFER_METHOD", "copyfile").lower()

def hash_password(plain_text: str) -> str:
    return hashlib.sha256(plain_text.encode('utf-8')).hexdigest()

def update_env_variable(key: str, value: str):
    set_key(ENV_PATH, key, value)

def prompt_for_credentials(set_user=True):
    if set_user:
        user = input("Enter new username: ").strip()
        if not user:
            print("Username cannot be empty.")
            sys.exit(1)
        update_env_variable("AUTH_USERNAME", user)
        print(f"✅ Updated AUTH_USERNAME = {user}")

    while True:
        pwd = getpass("Enter new password: ").strip()
        confirm = getpass("Confirm password: ").strip()
        if pwd != confirm:
            print("❌ Passwords do not match. Try again.")
        elif not pwd:
            print("❌ Password cannot be empty.")
        else:
            break

    hashed = hash_password(pwd)
    update_env_variable("AUTH_PASSWORD_HASH", hashed)
    print("✅ Password hash updated in .env")
    sys.exit(0)

class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    public_dir = "public"
    public_redirect_url = None

    def do_GET(self):
        path = unquote(self.path)

        try:
            if any(part.startswith('.') for part in path.strip('/').split('/')):
                self.send_error(404, "File not found")
                return

            if path.startswith(f'/{self.public_dir}'):
                full_path = self.translate_path(path)
                if os.path.isdir(full_path):
                    if self.public_redirect_url:
                        self.send_response(302)
                        self.send_header("Location", self.public_redirect_url)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(f"""
                            <html><head><meta http-equiv="refresh" content="0; url={self.public_redirect_url}"></head>
                            <body>Redirecting to <a href="{self.public_redirect_url}">{self.public_redirect_url}</a></body>
                            </html>
                        """.encode('utf-8'))
                        return
                    else:
                        self.send_error(403, "Directory listing denied")
                        return
                return super().do_GET()

            if not self.check_auth():
                self.send_auth_request()
                return

            return super().do_GET()

        except (BrokenPipeError, ConnectionResetError) as e:
            print(f"[WARN] Client disconnected during transfer: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected failure in do_GET: {e}")
            traceback.print_exc()

    def list_directory(self, path):
        try:
            entries = [e for e in os.listdir(path) if not e.startswith('.')]
        except OSError:
            self.send_error(404, "Directory not found")
            return None

        entries.sort()
        displaypath = os.path.relpath(path, os.getcwd())

        r = []
        r.append(f"<html><head><title>Index of /{displaypath}</title></head>")
        r.append(f"<body><h2>Index of /{displaypath}</h2><hr><ul>")

        for name in entries:
            full = os.path.join(path, name)
            display = name + '/' if os.path.isdir(full) else name
            link = name + '/' if os.path.isdir(full) else name
            r.append(f'<li><a href="{link}">{display}</a></li>')

        r.append("</ul><hr></body></html>")
        encoded = '\n'.join(r).encode('utf-8')
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        return None

    def check_auth(self):
        header = self.headers.get('Authorization')
        if not header or not header.startswith('Basic '):
            return False
        try:
            encoded = header.split(' ')[1]
            decoded = base64.b64decode(encoded).decode('utf-8')
            user, pwd = decoded.split(':', 1)
            return user == USERNAME and hash_password(pwd) == PASSWORD_HASH
        except Exception:
            return False

    def send_auth_request(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Protected Area"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Authentication required.')

    def copyfile(self, source, outputfile):
        if TRANSFER_METHOD == "sendfile":
            try:
                count = os.fstat(source.fileno()).st_size
                os.sendfile(outputfile.fileno(), source.fileno(), 0, count)
            except Exception as e:
                print(f"[WARN] sendfile() failed — falling back to copyfile(): {e}")
                traceback.print_exc()
                super().copyfile(source, outputfile)
        else:
            super().copyfile(source, outputfile)

def watch_threads():
    while True:
        for t in threading.enumerate():
            if not t.is_alive():
                print(f"[WARN] Thread {t.name} has stopped unexpectedly.")
        time.sleep(10)

def main():
    parser = argparse.ArgumentParser(description="Password-protected directory server.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to serve on")
    parser.add_argument("--public-dir", default=DEFAULT_PUBLIC_DIR, help="Public subdirectory name")
    parser.add_argument("--set-user", action="store_true", help="Prompt to set username and password in .env")
    parser.add_argument("--set-pass", action="store_true", help="Prompt to set password only in .env")
    args = parser.parse_args()

    if args.set_user:
        prompt_for_credentials(set_user=True)

    if args.set_pass:
        prompt_for_credentials(set_user=False)

    base_path = os.path.abspath(DEFAULT_SERVE_DIR)
    if not os.path.isdir(base_path):
        print(f"❌ Error: directory '{base_path}' not found or is not a directory.")
        sys.exit(1)

    public_path = os.path.join(base_path, args.public_dir)
    if not os.path.exists(public_path):
        try:
            os.makedirs(public_path)
            print(f"📁 Created missing public directory: {public_path}")
        except Exception as e:
            print(f"❌ Failed to create public directory '{public_path}': {e}")
            sys.exit(1)
    elif not os.path.isdir(public_path):
        print(f"❌ Error: '{public_path}' exists but is not a directory.")
        sys.exit(1)

    os.chdir(base_path)
    CustomHTTPRequestHandler.public_dir = args.public_dir
    CustomHTTPRequestHandler.public_redirect_url = DEFAULT_PUBLIC_REDIRECT

    print(f"✅ Serving directory: {base_path}")
    print(f"✅ Public subdirectory: /{args.public_dir}")
    print(f"✅ Listening on port: {args.port}")
    print(f"📦 Transfer method: {TRANSFER_METHOD}")

    with ThreadingHTTPServer(("", args.port), CustomHTTPRequestHandler) as httpd:
        watchdog = threading.Thread(target=watch_threads, daemon=True)
        watchdog.start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down...")

if __name__ == "__main__":
    main()
