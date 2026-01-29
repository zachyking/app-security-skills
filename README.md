# Secure Dev Skills

**Proactive security guidance for AI-assisted code generation.**

Research shows that 40-62% of AI-generated code contains exploitable security flaws. This Claude Code plugin shifts security left by providing real-time, stack-specific guidance during development—not just auditing after the fact.

## Overview

### The Problem

AI coding assistants frequently generate code with:
- SQL injection vulnerabilities (string concatenation in queries)
- Weak password hashing (MD5, SHA1, unsalted SHA256)
- XSS vulnerabilities (unsanitized output)
- Hardcoded secrets and API keys
- Command injection (shell=True, unsanitized exec)
- Broken access control (missing authorization checks)
- Insecure deserialization
- Path traversal vulnerabilities

### The Solution

This plugin provides **proactive** security guidance that:

1. **Asks about your context** - Task type, tech stack, security concerns
2. **Loads relevant skills** - Stack-specific patterns and anti-patterns
3. **Guides secure implementation** - Shows secure code examples before you write insecure code
4. **Catches common mistakes** - Flags anti-patterns specific to your framework

### Skills Included

| Skill | Description |
|-------|-------------|
| `/secure-dev:secure` | **Interactive assistant** - Asks questions, identifies your context, loads appropriate skills |
| `/secure-dev:secure-coding` | Universal patterns: secrets, validation, encoding, auth, crypto |
| `/secure-dev:dependency-security` | Supply chain: package validation, CVEs, typosquatting |
| `/secure-dev:infrastructure-security` | Cloud: network, IAM, storage, TLS, containers |
| `/secure-dev:llm-security` | AI apps: prompt injection, SHIELD framework, MCP security |
| `/secure-dev:secure-python` | Python, Django, Flask, FastAPI |
| `/secure-dev:secure-javascript` | Node.js, Express, Next.js, React |
| `/secure-dev:secure-java` | Java, Spring Boot |
| `/secure-dev:secure-dotnet` | C#, ASP.NET Core |
| `/secure-dev:secure-php` | PHP, Laravel, Symfony |
| `/secure-dev:secure-go` | Go, Gin, Echo |
| `/secure-dev:secure-mobile` | iOS (Swift), Android (Kotlin) |

---

## Installation

### From GitHub

```bash
# Clone the repository
git clone https://github.com/zachyking/app-security-skills.git
```

### Load During Development

Use the `--plugin-dir` flag to test the plugin:

```bash
claude --plugin-dir /path/to/app-security-skills
```

### Install via Marketplace

If this plugin is published to a marketplace, install with:

```bash
/plugin install secure-dev
```

Or add the marketplace URL to your Claude Code configuration first:

```bash
/plugin marketplace add https://github.com/zachyking/app-security-skills
```

### Verify Installation

Run `/help` in Claude Code - you should see the skills listed under the `secure-dev` namespace.

---

## Usage

### Interactive Mode (Recommended)

Start the interactive security assistant:

```
/secure-dev:secure
```

The assistant will guide you through:

1. **Task Type**
   - Code Review - Review existing code for vulnerabilities
   - New Development - Build features securely from the start
   - Architecture/Design - Plan secure system architecture
   - Infrastructure/Deployment - Secure cloud and CI/CD setup

2. **Tech Stack**
   - Python (Django, Flask, FastAPI)
   - JavaScript/TypeScript (Node.js, Express, Next.js, React)
   - Java (Spring Boot)
   - C#/.NET (ASP.NET Core)
   - PHP (Laravel, Symfony)
   - Go (Gin, Echo)
   - Mobile (iOS Swift, Android Kotlin)

3. **Security Focus**
   - Authentication & Authorization
   - Input Validation & Injection Prevention
   - Cryptography & Secrets Management
   - All Areas (comprehensive)

Then provides tailored guidance with secure code examples for your specific context.

### Direct Skill Access

If you know what you need, invoke skills directly:

```
/secure-dev:secure-python
/secure-dev:secure-javascript
/secure-dev:infrastructure-security
/secure-dev:dependency-security
```

### Example Session

```
You: /secure-dev:secure

Claude: I'll help ensure your development is secure. Let me understand your context.

**What type of task are you working on?**
○ Code Review
● New Development
○ Architecture/Design
○ Infrastructure/Deployment

You: New Development

Claude: **What is your primary technology stack?**
○ JavaScript/TypeScript
● Python
○ Java
○ Other

You: Python

Claude: **What security aspects are most relevant?**
☑ Authentication & Authorization
☐ Input Validation & Injection
☐ Cryptography & Secrets
☐ All Areas

You: Authentication & Authorization

Claude: For building authentication in **Python**, here are the secure patterns:

**Password Hashing - Use Argon2id (not MD5/SHA):**
```python
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
```

**Authorization - Always verify ownership:**
```python
@app.route('/documents/<doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)  # Don't just hide in UI—enforce server-side
    return doc
```

**Anti-Patterns to Avoid:**
- ❌ `hashlib.md5(password)` - Too fast, no salt
- ❌ `hashlib.sha256(password)` - Still too fast for passwords
- ❌ Checking permissions only in the frontend

Would you like me to help implement a complete auth system?
```

---

## Security Coverage

This plugin covers the OWASP Top 10 and common AI-generated vulnerabilities:

| Vulnerability | Skills That Cover It |
|---------------|---------------------|
| SQL Injection | All stack skills |
| XSS (Cross-Site Scripting) | secure-javascript, secure-php, secure-python, secure-java, secure-dotnet |
| Broken Access Control | All stack skills |
| Cryptographic Failures | secure-coding + all stack skills |
| Security Misconfiguration | infrastructure-security |
| Vulnerable Dependencies | dependency-security |
| Command Injection | All stack skills |
| Insecure Deserialization | secure-java, secure-php, secure-python |
| SSRF | All stack skills |
| Path Traversal | All stack skills |
| Prompt Injection | llm-security |
| Prototype Pollution | secure-javascript |
| XXE (XML External Entity) | secure-java, secure-dotnet |

---

## Plugin Structure

```
secure-dev-skills/
├── .claude-plugin/
│   └── plugin.json           # Plugin manifest
├── skills/
│   ├── secure/               # Interactive orchestrator
│   │   └── SKILL.md
│   ├── secure-coding/        # Universal patterns
│   │   └── SKILL.md
│   ├── dependency-security/
│   │   └── SKILL.md
│   ├── infrastructure-security/
│   │   └── SKILL.md
│   ├── llm-security/
│   │   └── SKILL.md
│   ├── secure-python/
│   │   └── SKILL.md
│   ├── secure-javascript/
│   │   └── SKILL.md
│   ├── secure-java/
│   │   └── SKILL.md
│   ├── secure-dotnet/
│   │   └── SKILL.md
│   ├── secure-php/
│   │   └── SKILL.md
│   ├── secure-go/
│   │   └── SKILL.md
│   └── secure-mobile/
│       └── SKILL.md
└── README.md
```

---

## How It Works

### Skill Architecture

```
┌─────────────────────────────────────────────────────────┐
│              /secure-dev:secure (Orchestrator)          │
│         Asks questions → Loads appropriate skills       │
└─────────────────────────┬───────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
┌─────────────────┐ ┌───────────┐ ┌─────────────────┐
│   Core Skills   │ │   Stack   │ │   Special Case  │
│                 │ │   Skills  │ │      Skills     │
│ • secure-coding │ │           │ │                 │
│ • dependency-   │ │ • python  │ │ • llm-security  │
│   security      │ │ • js/ts   │ │ • infrastructure│
│                 │ │ • java    │ │   -security     │
│                 │ │ • dotnet  │ │                 │
│                 │ │ • php     │ │                 │
│                 │ │ • go      │ │                 │
│                 │ │ • mobile  │ │                 │
└─────────────────┘ └───────────┘ └─────────────────┘
```

### Each Skill Provides

- **Secure patterns** - Correct implementations with code examples
- **Insecure patterns** - What to avoid with explanations of why
- **Framework-specific guidance** - Tailored to Django, Spring, Express, etc.
- **Security checklists** - Verification items before shipping
- **Anti-patterns to detect** - Common mistakes to flag during review

---

## Contributing

Contributions are welcome! Areas where help is needed:

- **Additional frameworks** - Ruby/Rails, Rust, Elixir/Phoenix
- **More vulnerability patterns** - Edge cases, new attack vectors
- **Testing** - Validation that skills trigger correctly
- **Documentation** - More examples, tutorials

Please open an issue or PR on GitHub.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

## Acknowledgments

- Security patterns informed by OWASP, CWE, and real-world vulnerability research
- Built to address findings from studies on AI-generated code security (Stanford, GitClear, Snyk)
