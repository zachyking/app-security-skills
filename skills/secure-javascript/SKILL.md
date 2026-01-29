---
name: secure-javascript
description: JavaScript/TypeScript security for Node.js, Express, Next.js, React - XSS, prototype pollution, JWT security. Use when writing JS/TS code.
---

# secure-javascript

Security patterns for JavaScript/TypeScript applications including Node.js, Express, Next.js, and React.

## When to Use

- Writing Node.js backend applications
- Using Express, Fastify, or Koa
- Building Next.js applications
- Creating React frontend applications
- Working with databases in JavaScript
- Implementing authentication/authorization in JS/TS

## Instructions

### SQL Injection Prevention

**Always use parameterized queries or ORM methods.**

```javascript
// INSECURE - SQL Injection vulnerable
app.get('/users', async (req, res) => {
    const query = `SELECT * FROM users WHERE id = ${req.query.id}`;
    const result = await db.query(query);
    res.json(result);
});

// INSECURE - Template literals are still string concatenation
const query = `SELECT * FROM users WHERE name = '${name}'`;

// SECURE - Parameterized query (pg)
app.get('/users', async (req, res) => {
    const query = 'SELECT * FROM users WHERE id = $1';
    const result = await db.query(query, [req.query.id]);
    res.json(result);
});

// SECURE - Parameterized query (mysql2)
const [rows] = await connection.execute(
    'SELECT * FROM users WHERE id = ?',
    [userId]
);

// SECURE - Prisma ORM
const user = await prisma.user.findUnique({
    where: { id: parseInt(userId) }
});

// SECURE - Drizzle ORM
const users = await db.select().from(usersTable).where(eq(usersTable.id, userId));

// SECURE - Knex.js query builder
const user = await knex('users').where('id', userId).first();
```

### XSS Prevention

**Never insert untrusted data directly into the DOM.**

```javascript
// INSECURE - XSS via innerHTML
document.getElementById('output').innerHTML = userInput;

// INSECURE - document.write
document.write(userInput);

// INSECURE - jQuery html()
$('#output').html(userInput);

// SECURE - Use textContent for plain text
document.getElementById('output').textContent = userInput;

// SECURE - jQuery text()
$('#output').text(userInput);

// SECURE - If HTML is needed, use DOMPurify
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);
document.getElementById('output').innerHTML = clean;

// SECURE - DOMPurify with strict config
const clean = DOMPurify.sanitize(userInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href']
});
```

**React-specific XSS prevention:**
```jsx
// React escapes by default - this is SECURE
function Comment({ text }) {
    return <div>{text}</div>;  // Auto-escaped
}

// INSECURE - dangerouslySetInnerHTML bypasses escaping
function Comment({ html }) {
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// SECURE - If HTML is needed, sanitize first
import DOMPurify from 'dompurify';

function Comment({ html }) {
    const clean = DOMPurify.sanitize(html);
    return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}

// INSECURE - href with user input can be javascript:
function Link({ url, text }) {
    return <a href={url}>{text}</a>;  // javascript:alert('xss')
}

// SECURE - Validate URL protocol
function Link({ url, text }) {
    const safeUrl = url.startsWith('http://') || url.startsWith('https://')
        ? url
        : '#';
    return <a href={safeUrl}>{text}</a>;
}
```

### Command Injection Prevention

**Never pass user input to shell commands.**

```javascript
// INSECURE - Command injection
const { exec } = require('child_process');
exec(`convert ${filename} output.png`, callback);  // ; rm -rf /

// INSECURE - Even with template literals
exec(`ls ${userPath}`, callback);

// SECURE - Use execFile with argument array
const { execFile } = require('child_process');
execFile('convert', [filename, 'output.png'], callback);

// SECURE - spawn with argument array
const { spawn } = require('child_process');
const process = spawn('convert', [filename, 'output.png']);

// SECURE - With input validation
const path = require('path');
const allowedDir = '/uploads';

function processFile(filename) {
    // Validate filename format
    if (!/^[\w\-. ]+$/.test(filename)) {
        throw new Error('Invalid filename');
    }

    // Ensure path is within allowed directory
    const fullPath = path.resolve(allowedDir, filename);
    if (!fullPath.startsWith(allowedDir)) {
        throw new Error('Path traversal detected');
    }

    execFile('convert', [fullPath, 'output.png'], callback);
}
```

### Path Traversal Prevention

**Validate all file paths against a base directory.**

```javascript
const path = require('path');
const fs = require('fs/promises');

// INSECURE - Path traversal vulnerable
app.get('/files/:name', async (req, res) => {
    const filePath = `./uploads/${req.params.name}`;
    const content = await fs.readFile(filePath);
    res.send(content);
});

// SECURE - Validate path is within allowed directory
app.get('/files/:name', async (req, res) => {
    const baseDir = path.resolve('./uploads');
    const filePath = path.resolve(baseDir, req.params.name);

    // Ensure resolved path is within base directory
    if (!filePath.startsWith(baseDir + path.sep)) {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const content = await fs.readFile(filePath);
        res.send(content);
    } catch (error) {
        res.status(404).json({ error: 'File not found' });
    }
});

// Express - Use express.static with proper config
app.use('/files', express.static('uploads', {
    dotfiles: 'deny',  // Reject dotfiles
    index: false       // Disable directory index
}));
```

### Authentication & Sessions

**Use secure session configuration and proper password hashing.**

```javascript
// INSECURE - Weak password hashing
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');

// SECURE - Use bcrypt
const bcrypt = require('bcrypt');
const saltRounds = 12;

async function hashPassword(password) {
    return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// Express session configuration
const session = require('express-session');
const RedisStore = require('connect-redis').default;

app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,  // From environment
    name: 'sessionId',  // Don't use default 'connect.sid'
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,        // HTTPS only
        httpOnly: true,      // No JavaScript access
        sameSite: 'lax',     // CSRF protection
        maxAge: 3600000,     // 1 hour
        domain: 'example.com'
    }
}));
```

**JWT best practices:**
```javascript
const jwt = require('jsonwebtoken');

// INSECURE - Weak secret, no expiration
const token = jwt.sign({ userId: 123 }, 'secret');

// INSECURE - Algorithm confusion vulnerability
const payload = jwt.verify(token, secret);  // Accepts 'none' algorithm

// SECURE - Strong secret, expiration, explicit algorithm
const token = jwt.sign(
    { userId: 123, type: 'access' },
    process.env.JWT_SECRET,  // Strong secret from environment
    {
        algorithm: 'HS256',
        expiresIn: '15m',  // Short-lived
        issuer: 'myapp',
        audience: 'myapp-users'
    }
);

// SECURE - Verify with explicit algorithm
const payload = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'],  // Only allow expected algorithm
    issuer: 'myapp',
    audience: 'myapp-users'
});
```

### CSRF Protection

**Implement CSRF tokens for state-changing operations.**

```javascript
// Express with csurf (for traditional forms)
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.get('/form', csrfProtection, (req, res) => {
    res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/submit', csrfProtection, (req, res) => {
    // CSRF token validated automatically
    res.json({ success: true });
});

// For SPA/API: Use SameSite cookies + custom header
app.use((req, res, next) => {
    // For state-changing requests, verify custom header
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
        const customHeader = req.headers['x-requested-with'];
        if (customHeader !== 'XMLHttpRequest') {
            return res.status(403).json({ error: 'CSRF validation failed' });
        }
    }
    next();
});
```

### Security Headers

**Configure security headers with Helmet.**

```javascript
const helmet = require('helmet');

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],  // Ideally remove unsafe-inline
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: true,
    frameguard: { action: 'deny' },
    hidePoweredBy: true,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: "none" },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    xssFilter: true,
}));
```

### Input Validation

**Validate all input with a schema validator.**

```javascript
// Using Zod (recommended)
import { z } from 'zod';

const UserSchema = z.object({
    username: z.string()
        .min(3)
        .max(30)
        .regex(/^[a-zA-Z0-9_]+$/, 'Invalid characters'),
    email: z.string().email(),
    password: z.string().min(12),
    age: z.number().int().positive().max(150).optional()
});

app.post('/users', async (req, res) => {
    try {
        const validatedData = UserSchema.parse(req.body);
        // Use validatedData safely
    } catch (error) {
        return res.status(400).json({ error: error.errors });
    }
});

// Using express-validator
const { body, validationResult } = require('express-validator');

app.post('/users', [
    body('username')
        .isLength({ min: 3, max: 30 })
        .matches(/^[a-zA-Z0-9_]+$/),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 12 })
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    // Process validated input
});
```

### Secure Random Generation

**Use crypto module for secure random values.**

```javascript
// INSECURE - Math.random is predictable
const token = Math.random().toString(36);
const id = Math.floor(Math.random() * 1000000);

// SECURE - crypto.randomBytes (Node.js)
const crypto = require('crypto');
const token = crypto.randomBytes(32).toString('hex');
const id = crypto.randomInt(1000000);  // Node 14.10+

// SECURE - crypto.randomUUID (Node.js 14.17+)
const uuid = crypto.randomUUID();

// SECURE - Browser
const array = new Uint8Array(32);
crypto.getRandomValues(array);
const token = Array.from(array, b => b.toString(16).padStart(2, '0')).join('');

// SECURE - Browser UUID
const uuid = crypto.randomUUID();
```

### Next.js-Specific Security

```typescript
// next.config.js - Security headers
const nextConfig = {
    async headers() {
        return [
            {
                source: '/(.*)',
                headers: [
                    {
                        key: 'X-Frame-Options',
                        value: 'DENY',
                    },
                    {
                        key: 'X-Content-Type-Options',
                        value: 'nosniff',
                    },
                    {
                        key: 'Referrer-Policy',
                        value: 'strict-origin-when-cross-origin',
                    },
                    {
                        key: 'Content-Security-Policy',
                        value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline';",
                    },
                ],
            },
        ];
    },
};

// API routes - validate input
// pages/api/users.ts
import { z } from 'zod';
import type { NextApiRequest, NextApiResponse } from 'next';

const CreateUserSchema = z.object({
    email: z.string().email(),
    name: z.string().min(1).max(100),
});

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method not allowed' });
    }

    try {
        const data = CreateUserSchema.parse(req.body);
        // Process validated data
    } catch (error) {
        return res.status(400).json({ error: 'Invalid input' });
    }
}

// Server Components - be careful with user data
// Don't pass unsanitized data to client components
async function UserProfile({ userId }: { userId: string }) {
    const user = await getUser(userId);
    // Sanitize before passing to client
    return <ClientComponent name={sanitize(user.name)} />;
}
```

### Prototype Pollution Prevention

```javascript
// INSECURE - Vulnerable to prototype pollution
function merge(target, source) {
    for (const key in source) {
        target[key] = source[key];  // Can set __proto__
    }
    return target;
}

// Attack: merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'))

// SECURE - Check for dangerous keys
function safeMerge(target, source) {
    const dangerousKeys = ['__proto__', 'constructor', 'prototype'];
    for (const key in source) {
        if (dangerousKeys.includes(key)) continue;
        if (!source.hasOwnProperty(key)) continue;
        target[key] = source[key];
    }
    return target;
}

// SECURE - Use Object.create(null) for dictionaries
const dict = Object.create(null);  // No prototype

// SECURE - Use Map for user-keyed data
const userSettings = new Map();
userSettings.set(userId, settings);
```

### Environment Variables

**Never hardcode secrets; always use environment variables.**

```javascript
// INSECURE - Hardcoded secrets
const API_KEY = 'sk-1234567890abcdef';
const DB_PASSWORD = 'password123';

// SECURE - Environment variables
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = process.env.DB_PASSWORD;

// Validate required env vars at startup
const requiredEnvVars = ['API_KEY', 'DB_PASSWORD', 'JWT_SECRET'];
for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
        console.error(`Missing required environment variable: ${envVar}`);
        process.exit(1);
    }
}

// Don't expose server env vars to client (Next.js)
// Only NEXT_PUBLIC_* vars are exposed to browser
// NEXT_PUBLIC_API_URL - visible to client
// API_SECRET - server only
```

## Security Checklist

- [ ] All SQL queries use parameterized statements
- [ ] No innerHTML/dangerouslySetInnerHTML with user data
- [ ] No child_process.exec with user input
- [ ] File paths validated against base directory
- [ ] Passwords hashed with bcrypt (cost 12+)
- [ ] Sessions configured with secure cookies
- [ ] JWT tokens have expiration and explicit algorithm
- [ ] Security headers configured (Helmet)
- [ ] All input validated with schema validator
- [ ] crypto module used for random values
- [ ] No prototype pollution vectors
- [ ] Secrets from environment variables

## Anti-Patterns to Flag

1. **Template literals in SQL** - `` `SELECT * FROM users WHERE id = ${id}` ``
2. **innerHTML with user data** - `element.innerHTML = userInput`
3. **exec() with user input** - `exec(\`command ${userInput}\`)`
4. **Math.random for security** - `Math.random().toString(36)`
5. **dangerouslySetInnerHTML** - Without DOMPurify sanitization
6. **Missing algorithm in JWT verify** - Allows algorithm confusion
7. **Hardcoded secrets** - `const API_KEY = 'sk-...'`
8. **MD5/SHA1 for passwords** - `crypto.createHash('md5')`
9. **Object spread with user data** - Prototype pollution risk
10. **Missing input validation** - No Zod/validator schema
