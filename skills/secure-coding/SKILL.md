---
name: secure-coding
description: Universal secure coding patterns - secrets management, input validation, output encoding, authentication, authorization, and cryptography. Use for any code generation task.
---

# secure-coding

Universal security patterns for generating secure code across all languages and frameworks.

## When to Use

- Any code generation task
- Writing new functions, classes, or modules
- Implementing authentication, authorization, or data handling
- Working with user input or external data
- Generating database queries or API calls

## Instructions

### Secret Management

**Never hardcode credentials, API keys, or tokens in source code.**

Required practices:
- Use environment variables for configuration secrets
- Use dedicated secret managers (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)
- Ensure `.env` files are in `.gitignore`
- Use different secrets per environment (dev/staging/prod)

```python
# INSECURE - Never do this
API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgres://user:password@host/db"

# SECURE - Use environment variables
import os
API_KEY = os.environ["API_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]
```

```javascript
// INSECURE
const apiKey = "sk-1234567890abcdef";

// SECURE
const apiKey = process.env.API_KEY;
```

### Input Validation

**Validate all input at system boundaries. Use allowlists over blocklists.**

Required practices:
- Validate type, length, format, and range
- Use parameterized queries for ALL database operations
- Sanitize input before processing
- Reject invalid input early with clear errors

```python
# INSECURE - SQL Injection vulnerable
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)

# SECURE - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

```javascript
// INSECURE - SQL Injection vulnerable
const query = `SELECT * FROM users WHERE id = ${userId}`;

// SECURE - Parameterized query
const query = "SELECT * FROM users WHERE id = $1";
await client.query(query, [userId]);
```

```python
# Input validation example
import re

def validate_email(email: str) -> bool:
    """Validate email format with allowlist approach."""
    if not email or len(email) > 254:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_username(username: str) -> bool:
    """Validate username with strict allowlist."""
    if not username or len(username) < 3 or len(username) > 30:
        return False
    # Only allow alphanumeric and underscore
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))
```

### Output Encoding

**Apply context-aware encoding to prevent injection attacks.**

Required practices:
- HTML encode for HTML context
- JavaScript encode for JS context
- URL encode for URL parameters
- Use framework auto-escaping features

```python
# INSECURE - XSS vulnerable
return f"<div>Welcome, {username}</div>"

# SECURE - HTML encoding
from html import escape
return f"<div>Welcome, {escape(username)}</div>"

# SECURE - Use template engine with auto-escaping (Jinja2)
# Template: <div>Welcome, {{ username }}</div>
# Auto-escapes by default
```

```javascript
// INSECURE - XSS vulnerable
element.innerHTML = `<div>Welcome, ${username}</div>`;

// SECURE - Use textContent for plain text
element.textContent = `Welcome, ${username}`;

// SECURE - Use DOMPurify for HTML content
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userContent);
```

### Authentication

**Use proven authentication patterns with secure defaults.**

Required practices:
- Use Argon2id or bcrypt for password hashing (NEVER MD5, SHA1, or SHA256 alone)
- Implement rate limiting on authentication endpoints
- Use secure session management
- Implement proper logout (invalidate sessions)

```python
# INSECURE - Weak hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# SECURE - Use Argon2id
from argon2 import PasswordHasher
ph = PasswordHasher()
password_hash = ph.hash(password)

# Verification
try:
    ph.verify(password_hash, password)
except argon2.exceptions.VerifyMismatchError:
    raise AuthenticationError("Invalid password")
```

```javascript
// INSECURE - Weak hashing
const hash = crypto.createHash('md5').update(password).digest('hex');

// SECURE - Use bcrypt
import bcrypt from 'bcrypt';
const saltRounds = 12;
const hash = await bcrypt.hash(password, saltRounds);

// Verification
const valid = await bcrypt.compare(password, hash);
```

**Session Management:**
```python
# Secure session cookie settings
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # No JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)
```

### Authorization

**Implement proper access control on every resource access.**

Required practices:
- Check authorization on every request (not just UI hiding)
- Verify resource ownership before access
- Use role-based access control (RBAC) or attribute-based (ABAC)
- Prevent Insecure Direct Object References (IDOR)

```python
# INSECURE - IDOR vulnerable
@app.route('/documents/<doc_id>')
def get_document(doc_id):
    return Document.query.get(doc_id)

# SECURE - Ownership verification
@app.route('/documents/<doc_id>')
@login_required
def get_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    if document.owner_id != current_user.id:
        abort(403)
    return document
```

```javascript
// INSECURE - No authorization check
app.get('/api/orders/:id', async (req, res) => {
    const order = await Order.findById(req.params.id);
    res.json(order);
});

// SECURE - Verify ownership
app.get('/api/orders/:id', authenticate, async (req, res) => {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Not found' });
    if (order.userId !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(order);
});
```

### Cryptography

**Use modern, well-vetted cryptographic algorithms.**

Required practices:
- AES-256-GCM for symmetric encryption
- RSA-2048+ or ECDSA for asymmetric operations
- Use cryptographically secure random number generators
- Never implement custom cryptography

```python
# INSECURE - Weak encryption and random
import random
from Crypto.Cipher import DES
key = str(random.randint(0, 99999999)).encode()

# SECURE - AES-256-GCM with secure random
from cryptography.fernet import Fernet
from secrets import token_bytes

key = Fernet.generate_key()  # Uses secure random internally
cipher = Fernet(key)
encrypted = cipher.encrypt(plaintext.encode())
```

```javascript
// INSECURE - Math.random is not cryptographically secure
const token = Math.random().toString(36);

// SECURE - Use crypto API
const token = crypto.randomBytes(32).toString('hex');

// Browser
const array = new Uint8Array(32);
crypto.getRandomValues(array);
```

### Dangerous Functions to Avoid

**These functions are high-risk and should be avoided or used with extreme caution:**

| Language | Dangerous | Safer Alternative |
|----------|-----------|-------------------|
| Python | `eval()`, `exec()` | `ast.literal_eval()` for data |
| Python | `pickle.loads()` on untrusted data | `json.loads()` |
| Python | `subprocess.run(shell=True)` | `subprocess.run(['cmd', 'arg'])` |
| JavaScript | `eval()` | `JSON.parse()` for data |
| JavaScript | `innerHTML` with user data | `textContent` or DOMPurify |
| JavaScript | `new Function()` | Avoid dynamic code execution |
| PHP | `eval()`, `system()`, `exec()` | Parameterized alternatives |
| Any | String concatenation for SQL | Parameterized queries |
| Any | String concatenation for shell | Argument arrays |

```python
# INSECURE - Command injection
import subprocess
subprocess.run(f"convert {filename} output.png", shell=True)

# SECURE - Argument array
subprocess.run(["convert", filename, "output.png"], check=True)
```

### Error Handling

**Handle errors securely without leaking sensitive information.**

Required practices:
- Log detailed errors server-side
- Return generic errors to clients
- Never expose stack traces in production
- Use structured error responses

```python
# INSECURE - Leaks sensitive info
@app.errorhandler(Exception)
def handle_error(e):
    return str(e), 500  # Exposes internal details

# SECURE - Generic client error, detailed logging
import logging
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    logger.exception("Internal error occurred")
    return {"error": "An internal error occurred"}, 500
```

### File Operations

**Handle file uploads and operations securely.**

Required practices:
- Validate file types by content, not just extension
- Generate new filenames (don't trust user input)
- Store uploads outside web root
- Set size limits

```python
# INSECURE - Path traversal vulnerable
filename = request.form['filename']
with open(f'/uploads/{filename}', 'rb') as f:
    return f.read()

# SECURE - Sanitize filename and validate path
import os
from werkzeug.utils import secure_filename

filename = secure_filename(request.form['filename'])
filepath = os.path.join('/uploads', filename)
# Ensure path is within allowed directory
if not os.path.abspath(filepath).startswith('/uploads/'):
    abort(400)
```

## Anti-Patterns to Detect

When reviewing or generating code, flag these patterns:

1. **Hardcoded secrets** - Any string that looks like an API key, password, or token
2. **String concatenation in queries** - SQL, LDAP, or command injection risk
3. **eval/exec on user input** - Code injection
4. **MD5/SHA1 for passwords** - Weak hashing
5. **Math.random for security** - Predictable values
6. **Missing authorization checks** - IDOR vulnerabilities
7. **innerHTML with user data** - XSS vulnerabilities
8. **shell=True with user input** - Command injection
9. **Disabled TLS verification** - MitM vulnerability
10. **Broad exception catching** - May hide security issues

## Security Checklist

Before generating code, verify:

- [ ] No hardcoded secrets
- [ ] All user input validated
- [ ] Database queries parameterized
- [ ] Output properly encoded for context
- [ ] Authentication uses strong hashing
- [ ] Authorization checked on every resource access
- [ ] Cryptography uses modern algorithms
- [ ] No dangerous functions with untrusted input
- [ ] Errors logged securely without leaking info
- [ ] File operations sanitize paths and validate content
