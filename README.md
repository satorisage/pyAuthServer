# 🔐 Auth File Server

A lightweight, password-protected HTTP file server written in Python.  
It serves directory listings, supports a public folder with redirect behavior, hides hidden files, and is fully configurable via a `.env` file.

---

## 🚀 Features

- 🔒 Basic authentication with SHA256 password hashing
- 📁 Directory listing (excluding hidden files)
- 🌐 Public folder that **does not show directory index**
- 🔁 Public folder can optionally **redirect to a URL**
- 🔄 Configurable file transfer method: `copyfile` or `sendfile`
- ⚙️ `.env` support for clean configuration
- 🧵 Threaded server for concurrent downloads
- 📦 Docker and systemd compatible
- 🧪 Interactive setup with `--set-user` and `--set-pass`

---

## 📦 Requirements

- Python 3.7+
- [`python-dotenv`](https://pypi.org/project/python-dotenv/)

Install with:

```bash
pip3 install python-dotenv
```

---

## ⚙️ Configuration

Create a `.env` file in the same directory as `auth_server.py`:

```env
AUTH_USERNAME=peoriait
AUTH_PASSWORD_HASH=<your_sha256_hash>
AUTH_PORT=8080
AUTH_PUBLIC_DIR=public
AUTH_SERVE_DIR=.
AUTH_PUBLIC_REDIRECT=https://www.peoriait.com
TRANSFER_METHOD=copyfile
```

---

## 🔐 Password Hashing

To create a password hash:

```bash
python3 auth_server.py --set-user
```

Or to just update the password:

```bash
python3 auth_server.py --set-pass
```

This safely hashes the password and updates your `.env`.

---

## 🏃 Usage

Start the server:

```bash
python3 auth_server.py
```

Serve from a different port or public directory:

```bash
python3 auth_server.py --port 9090 --public-dir media
```

---

## 🚧 Public Folder Behavior

- Files inside the **public folder** do not require authentication
- Directories inside it are **not listed**
- Accessing the folder root (e.g. `/public/`) redirects to `AUTH_PUBLIC_REDIRECT`

---

## ⚡ Transfer Method

You can choose between two file transfer methods:

| Method     | Description                          | Recommended when…                         |
|------------|--------------------------------------|--------------------------------------------|
| `copyfile` | Buffered transfer (safe, default)    | ✅ Portable and stable everywhere           |
| `sendfile` | Zero-copy OS syscall (faster)        | ⚠️ High-performance, but may fail in LXC    |

Set in `.env`:

```env
TRANSFER_METHOD=copyfile
```

---

## 🧪 Testing Speed

To test raw performance of the server, try `curl` or `wget`:

```bash
curl -O http://<host>:<port>/<filename>
```

---

## 🐳 Docker (Optional)

If you'd like to run this with Docker Compose:

```yaml
version: '3.8'
services:
  auth-server:
    image: python:3
    working_dir: /app
    volumes:
      - ./auth_server.py:/app/auth_server.py
      - ./files:/app/files
      - ./public:/app/files/public
      - ./auth.env:/app/.env
    ports:
      - "8080:8080"
    command: python3 auth_server.py
```

---

## 🖥 systemd Service (Linux)

You can also run this as a service. Create a systemd file like:

```ini
[Unit]
Description=Python Auth File Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/auth-server/auth_server.py
WorkingDirectory=/opt/auth-server
EnvironmentFile=/opt/auth-server/.env
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable with:

```bash
sudo systemctl daemon-reexec
sudo systemctl enable --now auth-server
```

---

## 🛡 Security Notes

- All credentials are stored in `.env` — protect it like a password
- SHA256 is used for password hashing, not bcrypt (for simplicity)
- No HTTPS built-in — use a reverse proxy (like Nginx) for encryption

---

## 🙌 Credits

Built with ❤️ by PeoriaIT.

---

## 📜 License

MIT
