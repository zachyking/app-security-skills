---
name: dependency-security
description: Supply chain security - package validation, CVE awareness, typosquatting detection, version pinning. Use when adding or updating dependencies.
---

# dependency-security

Prevent supply chain attacks, package hallucination, and vulnerable dependency usage.

## When to Use

- Adding new packages or dependencies to a project
- Recommending libraries or frameworks
- Updating existing dependencies
- Reviewing package.json, requirements.txt, Gemfile, or similar
- Discussing third-party library choices

## Instructions

### Package Verification

**Before recommending any package, verify it exists and is legitimate.**

Required checks:
1. Verify the package exists on the official registry
2. Check for typosquatting (similar names to popular packages)
3. Review package age (be cautious of packages < 30 days old)
4. Check download counts and community adoption
5. Verify the publisher/maintainer reputation

```
Common typosquatting patterns to watch:
- lodash vs lodahs, loadsh
- requests vs request, reqeusts
- tensorflow vs tensorfow, tensor-flow
- pytorch vs pytoroch, py-torch
- numpy vs numpi, numpie
- bittensor vs bitensor
- crossenv vs cross-env (npm incident)
```

**When recommending packages:**
```
I recommend using `package-name` for this task.
- Registry: https://www.npmjs.com/package/package-name
- Downloads: X weekly
- Last updated: YYYY-MM-DD
- Known vulnerabilities: None current / CVE-XXXX-XXXX (patched in vX.X)
```

### Known Vulnerable Packages

**Avoid these packages or ensure patched versions:**

| Package | Issue | Alternative/Fix |
|---------|-------|-----------------|
| `event-stream` (npm) | Malicious code injection | Removed, use alternatives |
| `ua-parser-js` < 0.7.30 | Supply chain attack | Update to >= 0.7.30 |
| `colors` >= 1.4.1 | Sabotage by maintainer | Pin to 1.4.0 or use `chalk` |
| `node-ipc` >= 10.1.1 | Protestware | Pin to < 10.1.1 or fork |
| `log4j` < 2.17.1 | RCE (Log4Shell) | Update to >= 2.17.1 |
| `spring-core` < 5.3.18 | RCE (Spring4Shell) | Update to >= 5.3.18 |
| `lodash` < 4.17.21 | Prototype pollution | Update to >= 4.17.21 |
| `axios` < 0.21.1 | SSRF vulnerability | Update to >= 0.21.1 |
| `serialize-javascript` < 3.1.0 | XSS vulnerability | Update to >= 3.1.0 |
| `minimist` < 1.2.6 | Prototype pollution | Update to >= 1.2.6 |

### Outdated Library Patterns

**Replace deprecated/insecure libraries with modern alternatives:**

| Outdated | Issue | Modern Alternative |
|----------|-------|-------------------|
| `md5` / `sha1` for passwords | Weak hashing | `argon2`, `bcrypt` |
| `moment.js` | Unmaintained, large | `date-fns`, `dayjs`, `luxon` |
| `request` (npm) | Deprecated | `node-fetch`, `axios`, `got` |
| `crypto-js` for hashing | Often misused | Native `crypto` module |
| `querystring` | Deprecated in Node | `URLSearchParams` |
| `url.parse()` | Deprecated | `new URL()` |
| `bodyParser` (Express) | Included in Express | `express.json()`, `express.urlencoded()` |
| `node-uuid` | Renamed | `uuid` |
| `randomstring` | Not crypto-secure | `crypto.randomBytes()` |
| Python `optparse` | Deprecated | `argparse` |
| Python `imp` | Deprecated | `importlib` |
| Python `asyncio.coroutine` | Deprecated | `async def` |
| `mysql` (Python) | Unmaintained | `mysql-connector-python`, `pymysql` |
| `pycrypto` | Unmaintained | `cryptography`, `pycryptodome` |

### Version Pinning

**Pin versions appropriately for the context.**

For production applications:
```json
// package.json - SECURE: Exact versions
{
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21"
  }
}
```

```python
# requirements.txt - SECURE: Pinned with hash verification
package-name==1.2.3 --hash=sha256:abc123...
```

```
# INSECURE patterns to avoid:
"*"           # Any version
"latest"      # Unpredictable
">=1.0.0"     # Too permissive
"^1.0.0"      # May include breaking changes (in some ecosystems)
```

**Use lock files:**
- npm: `package-lock.json`
- yarn: `yarn.lock`
- pip: `requirements.txt` with hashes, or `poetry.lock`
- bundler: `Gemfile.lock`
- cargo: `Cargo.lock`

### Vulnerability Checking Commands

**Include vulnerability checks in development workflow:**

```bash
# npm
npm audit
npm audit fix

# yarn
yarn audit

# pip (with pip-audit)
pip-audit

# Python (with safety)
safety check -r requirements.txt

# Ruby
bundle audit

# Go
go list -json -m all | nancy sleuth
# or
govulncheck ./...

# .NET
dotnet list package --vulnerable

# Cargo (Rust)
cargo audit
```

### Dependency Review Checklist

When adding a new dependency:

- [ ] **Necessity**: Is this dependency actually needed, or can stdlib solve it?
- [ ] **Registry verification**: Package exists on official registry
- [ ] **Typosquatting check**: Name matches intended package exactly
- [ ] **Age check**: Package is not newly created (< 30 days without good reason)
- [ ] **Maintenance**: Updated within last year, responsive maintainers
- [ ] **Security history**: No unpatched CVEs
- [ ] **License compatibility**: License is compatible with project
- [ ] **Dependency tree**: Transitive dependencies are reasonable
- [ ] **Bundle size**: Appropriate for the functionality (JS especially)

### Red Flags in Packages

**Be suspicious of packages that:**

1. Have very few downloads but claim to be popular
2. Were created very recently for a common task
3. Have names very similar to popular packages
4. Request unusual permissions (network for a string utility)
5. Have obfuscated code in install scripts
6. Have single maintainers with no history
7. Have postinstall scripts that download external code
8. Have dependencies that don't match their stated purpose

### Security-Focused Package Alternatives

**When a standard library or built-in can do the job:**

```javascript
// Instead of: uuid package for simple IDs
// Use: crypto.randomUUID() (Node 14.17+, all modern browsers)
const id = crypto.randomUUID();

// Instead of: is-even, is-odd packages
// Use: basic math
const isEven = n => n % 2 === 0;

// Instead of: left-pad (famously)
// Use: String.prototype.padStart()
'5'.padStart(3, '0'); // "005"
```

```python
# Instead of: requests for simple HTTP (if acceptable)
# Use: urllib.request (stdlib)
from urllib.request import urlopen
response = urlopen('https://api.example.com')

# Instead of: python-dotenv for basic env loading
# Just use: os.environ (if already set by deployment)
import os
api_key = os.environ['API_KEY']
```

### Subresource Integrity (SRI)

**For CDN-loaded scripts, always use SRI:**

```html
<!-- INSECURE - No integrity check -->
<script src="https://cdn.example.com/lib.js"></script>

<!-- SECURE - With SRI -->
<script
  src="https://cdn.example.com/lib.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
  crossorigin="anonymous">
</script>
```

Generate SRI hashes:
```bash
# Generate SRI hash
openssl dgst -sha384 -binary file.js | openssl base64 -A

# Or use online tool: https://www.srihash.org/
```

### Package Manager Security Settings

**npm:**
```bash
# Audit before install
npm set audit true

# Ignore scripts during install (review manually)
npm install --ignore-scripts

# Check scripts before running
npm show <package> scripts
```

**pip:**
```bash
# Use hash verification
pip install --require-hashes -r requirements.txt

# Prevent execution during install
pip install --no-cache-dir --no-compile package-name
```

## Anti-Patterns to Flag

1. **Installing unverified packages** - No verification of package existence
2. **Wildcard versions** - `"*"` or `"latest"` in dependencies
3. **Missing lock files** - No lock file committed to repository
4. **Ignoring audit warnings** - Running `npm audit` but ignoring results
5. **Typosquatting susceptibility** - Similar names to popular packages
6. **Outdated critical packages** - Known vulnerable versions in use
7. **Excessive dependencies** - 100+ deps for simple functionality
8. **Missing SRI** - CDN scripts without integrity attributes
9. **No dependency review** - Adding packages without vetting
10. **Transitive vulnerability ignorance** - Only checking direct dependencies
