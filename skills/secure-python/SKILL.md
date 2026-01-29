---
name: secure-python
description: Python security for Django, Flask, FastAPI - SQL injection, command injection, YAML safety, password hashing. Use when writing Python code.
---

# secure-python

Security patterns for Python applications including Django, Flask, and FastAPI.

## When to Use

- Writing Python web applications
- Using Django, Flask, FastAPI, or other web frameworks
- Building REST APIs in Python
- Working with databases (SQLAlchemy, Django ORM)
- Processing user input or file uploads
- Implementing authentication/authorization

## Instructions

### SQL Injection Prevention

**Always use parameterized queries or ORM methods.**

```python
# INSECURE - SQL Injection vulnerable
def get_user(username):
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()

# INSECURE - Even with .format()
def get_user(username):
    query = "SELECT * FROM users WHERE username = '{}'".format(username)
    cursor.execute(query)

# SECURE - Parameterized query (psycopg2)
def get_user(username):
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    return cursor.fetchone()

# SECURE - SQLAlchemy ORM
def get_user(username):
    return session.query(User).filter(User.username == username).first()

# SECURE - SQLAlchemy Core with text()
from sqlalchemy import text
def get_user(username):
    result = session.execute(
        text("SELECT * FROM users WHERE username = :username"),
        {"username": username}
    )
    return result.fetchone()

# SECURE - Django ORM
def get_user(username):
    return User.objects.filter(username=username).first()
```

### Command Injection Prevention

**Never use shell=True with user input. Use argument lists.**

```python
import subprocess

# INSECURE - Command injection vulnerable
def convert_file(filename):
    subprocess.run(f"convert {filename} output.png", shell=True)
    # Attack: filename = "; rm -rf /"

# INSECURE - Even with shlex.quote, shell=True is risky
import shlex
def convert_file(filename):
    subprocess.run(f"convert {shlex.quote(filename)} output.png", shell=True)

# SECURE - Use argument list (no shell)
def convert_file(filename):
    subprocess.run(["convert", filename, "output.png"], check=True)

# SECURE - With input validation
import re
from pathlib import Path

def convert_file(filename):
    # Validate filename format
    if not re.match(r'^[\w\-. ]+$', filename):
        raise ValueError("Invalid filename")

    # Ensure file exists in expected directory
    file_path = Path("/uploads") / filename
    if not file_path.resolve().is_relative_to(Path("/uploads").resolve()):
        raise ValueError("Invalid path")

    subprocess.run(["convert", str(file_path), "output.png"], check=True)
```

### Dangerous Function Avoidance

**Never use eval(), exec(), or pickle on untrusted input.**

```python
# INSECURE - Code injection via eval
def calculate(expression):
    return eval(expression)  # eval("__import__('os').system('rm -rf /')")

# SECURE - Use ast.literal_eval for data structures
import ast
def parse_data(data_string):
    return ast.literal_eval(data_string)  # Only literals, no code execution

# SECURE - Use specific parsers for specific formats
import json
def parse_json(json_string):
    return json.loads(json_string)

# INSECURE - Pickle deserialization
import pickle
def load_data(data):
    return pickle.loads(data)  # Arbitrary code execution

# SECURE - Use JSON or other safe formats
import json
def load_data(data):
    return json.loads(data)

# If pickle is REQUIRED, use restricted unpickler
import io
import pickle

class RestrictedUnpickler(pickle.Unpickler):
    ALLOWED_CLASSES = {
        ('myapp.models', 'SafeModel'),
    }

    def find_class(self, module, name):
        if (module, name) not in self.ALLOWED_CLASSES:
            raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")
        return super().find_class(module, name)
```

### Password Hashing

**Use Argon2id or bcrypt, never MD5/SHA1/SHA256 alone.**

```python
# INSECURE - Weak hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
password_hash = hashlib.sha256(password.encode()).hexdigest()

# SECURE - Argon2id (recommended)
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()

def hash_password(password: str) -> str:
    return ph.hash(password)

def verify_password(password: str, hash: str) -> bool:
    try:
        ph.verify(hash, password)
        return True
    except VerifyMismatchError:
        return False

# SECURE - bcrypt
import bcrypt

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode(), salt).decode()

def verify_password(password: str, hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), hash.encode())

# Django automatically uses PBKDF2 by default, but you can use Argon2
# settings.py
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]
```

### XSS Prevention

**Use template auto-escaping and be careful with safe/raw markers.**

```python
# Django Templates - Auto-escaped by default
# template.html: {{ user_input }}  <- Escaped
# template.html: {{ user_input|safe }}  <- DANGEROUS if user_input is untrusted

# INSECURE - Marking user input as safe
def view(request):
    user_comment = request.POST['comment']
    return render(request, 'page.html', {'comment': mark_safe(user_comment)})

# SECURE - Let Django escape automatically
def view(request):
    user_comment = request.POST['comment']
    return render(request, 'page.html', {'comment': user_comment})

# Flask/Jinja2 - Auto-escaped by default
# template.html: {{ user_input }}  <- Escaped
# template.html: {{ user_input|safe }}  <- DANGEROUS

# INSECURE - Rendering HTML from user
from flask import Markup
@app.route('/comment')
def show_comment():
    comment = request.args.get('comment')
    return Markup(comment)  # XSS vulnerability

# SECURE - Escape user input
from markupsafe import escape
@app.route('/comment')
def show_comment():
    comment = request.args.get('comment')
    return escape(comment)

# If HTML is needed, use a sanitizer
import bleach
def sanitize_html(html: str) -> str:
    allowed_tags = ['p', 'br', 'strong', 'em', 'a']
    allowed_attrs = {'a': ['href']}
    return bleach.clean(html, tags=allowed_tags, attributes=allowed_attrs)
```

### CSRF Protection

**Enable CSRF protection in all frameworks.**

```python
# Django - CSRF enabled by default
# Ensure middleware is present:
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    # ...
]

# In templates:
# <form method="post">{% csrf_token %}...</form>

# For AJAX, include CSRF token in headers
# X-CSRFToken: {{ csrf_token }}

# Flask - Use Flask-WTF
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
csrf = CSRFProtect(app)

# In templates:
# <form method="post">{{ csrf_token() }}...</form>

# FastAPI - For session-based apps, implement CSRF
# For pure API with token auth, CSRF may not be needed
```

### Path Traversal Prevention

**Validate file paths are within expected directories.**

```python
from pathlib import Path

# INSECURE - Path traversal vulnerable
def get_file(filename):
    with open(f'/uploads/{filename}', 'rb') as f:
        return f.read()
    # Attack: filename = "../../../etc/passwd"

# SECURE - Validate path is within allowed directory
def get_file(filename: str) -> bytes:
    base_path = Path('/uploads').resolve()
    file_path = (base_path / filename).resolve()

    # Ensure the resolved path is within base directory
    if not file_path.is_relative_to(base_path):
        raise ValueError("Invalid file path")

    if not file_path.exists():
        raise FileNotFoundError("File not found")

    return file_path.read_bytes()

# Django - Use FilePathField with path validation
# Flask - Use send_from_directory which validates paths
from flask import send_from_directory

@app.route('/files/<path:filename>')
def serve_file(filename):
    return send_from_directory('/uploads', filename)  # Validates path
```

### YAML Safety

**Never use yaml.load() with untrusted data.**

```python
import yaml

# INSECURE - Arbitrary code execution
with open('config.yaml') as f:
    data = yaml.load(f)  # Can execute arbitrary Python code

# INSECURE - Even with Loader, some are unsafe
data = yaml.load(content, Loader=yaml.Loader)  # Still dangerous

# SECURE - Use safe_load
with open('config.yaml') as f:
    data = yaml.safe_load(f)  # Only basic Python types

# SECURE - Explicit SafeLoader
data = yaml.load(content, Loader=yaml.SafeLoader)
```

### Django-Specific Security

```python
# settings.py - Security settings

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')

# Security middleware (order matters)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    # ...
]

# HTTPS settings
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Cookie security
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# Content security
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
```

### Flask-Specific Security

```python
from flask import Flask, session
from flask_talisman import Talisman

app = Flask(__name__)

# Secret key from environment
app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']

# Session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
)

# Security headers with Flask-Talisman
Talisman(
    app,
    force_https=True,
    strict_transport_security=True,
    session_cookie_secure=True,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self'",
        'style-src': "'self'",
    }
)
```

### FastAPI-Specific Security

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI()

# Restrict allowed hosts
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["example.com", "*.example.com"]
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],  # Not "*" in production
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Input validation with Pydantic
from pydantic import BaseModel, EmailStr, validator
import re

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

    @validator('username')
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]{3,30}$', v):
            raise ValueError('Invalid username format')
        return v

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 12:
            raise ValueError('Password must be at least 12 characters')
        return v

@app.post("/users")
async def create_user(user: UserCreate):
    # Pydantic validates input automatically
    return {"username": user.username}
```

### Secure Random Numbers

```python
# INSECURE - Predictable random
import random
token = ''.join(random.choices('abcdef0123456789', k=32))

# SECURE - Cryptographically secure random
import secrets

# Generate secure token
token = secrets.token_hex(32)  # 64 character hex string
token = secrets.token_urlsafe(32)  # URL-safe base64

# Generate secure password
password = secrets.token_urlsafe(16)

# Secure random choice
secure_choice = secrets.choice(['a', 'b', 'c'])

# Secure random integer
secure_int = secrets.randbelow(100)  # 0 to 99
```

## Security Checklist

- [ ] All database queries parameterized
- [ ] No shell=True with user input
- [ ] No eval/exec/pickle on untrusted data
- [ ] Passwords hashed with Argon2id or bcrypt
- [ ] Template auto-escaping not bypassed
- [ ] CSRF protection enabled
- [ ] File paths validated against traversal
- [ ] yaml.safe_load used instead of yaml.load
- [ ] secrets module used for random tokens
- [ ] Security middleware/headers configured
- [ ] DEBUG=False in production
- [ ] SECRET_KEY from environment variable

## Anti-Patterns to Flag

1. **String formatting in SQL** - `f"SELECT * FROM users WHERE id = {id}"`
2. **shell=True with variables** - `subprocess.run(cmd, shell=True)`
3. **eval() on user input** - `eval(user_expression)`
4. **pickle.loads() on untrusted data** - Arbitrary code execution
5. **yaml.load() without SafeLoader** - Code execution via YAML
6. **MD5/SHA for passwords** - `hashlib.md5(password)`
7. **mark_safe() on user input** - XSS via Django
8. **random module for security** - `random.randint()` for tokens
9. **DEBUG=True in production** - Information disclosure
10. **Hardcoded SECRET_KEY** - Session forgery
