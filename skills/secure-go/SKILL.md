---
name: secure-go
description: Go security for Gin, Echo - SQL injection, command injection, template security, cryptography. Use when writing Go code.
---

# secure-go

Security patterns for Go applications including web frameworks like Gin and Echo.

## When to Use

- Writing Go web applications or APIs
- Using Gin, Echo, Fiber, or standard net/http
- Working with databases (database/sql, GORM, sqlx)
- Implementing authentication/authorization in Go
- Processing user input or handling file operations
- Working with cryptography in Go

## Instructions

### SQL Injection Prevention

**Always use parameterized queries with placeholders.**

```go
// INSECURE - SQL Injection vulnerable
func getUser(db *sql.DB, username string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
    row := db.QueryRow(query)
    // ...
}

// INSECURE - Even with + concatenation
query := "SELECT * FROM users WHERE id = " + userID

// SECURE - Parameterized query with database/sql
func getUser(db *sql.DB, username string) (*User, error) {
    query := "SELECT id, username, email FROM users WHERE username = $1"
    row := db.QueryRow(query, username)

    var user User
    err := row.Scan(&user.ID, &user.Username, &user.Email)
    return &user, err
}

// SECURE - Using sqlx
func getUser(db *sqlx.DB, username string) (*User, error) {
    var user User
    err := db.Get(&user, "SELECT * FROM users WHERE username = $1", username)
    return &user, err
}

// SECURE - Using GORM
func getUser(db *gorm.DB, username string) (*User, error) {
    var user User
    result := db.Where("username = ?", username).First(&user)
    return &user, result.Error
}

// SECURE - GORM with struct conditions
db.Where(&User{Username: username}).First(&user)
```

### Command Injection Prevention

**Never pass user input to shell commands. Use exec.Command with argument arrays.**

```go
// INSECURE - Command injection via shell
func processFile(filename string) error {
    cmd := exec.Command("sh", "-c", "cat "+filename)
    return cmd.Run()
}

// INSECURE - fmt.Sprintf into command string
cmdStr := fmt.Sprintf("convert %s output.png", filename)
exec.Command("sh", "-c", cmdStr).Run()

// SECURE - Use exec.Command with separate arguments
func processFile(filename string) error {
    cmd := exec.Command("cat", filename)  // Arguments separated
    return cmd.Run()
}

// SECURE - With input validation
func processFile(filename string) ([]byte, error) {
    // Validate filename format
    if !regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`).MatchString(filename) {
        return nil, errors.New("invalid filename")
    }

    // Ensure path is within allowed directory
    basePath := "/uploads"
    fullPath := filepath.Join(basePath, filename)
    absPath, err := filepath.Abs(fullPath)
    if err != nil || !strings.HasPrefix(absPath, basePath) {
        return nil, errors.New("invalid path")
    }

    cmd := exec.Command("file", absPath)
    return cmd.Output()
}
```

### Path Traversal Prevention

**Validate file paths against allowed directories.**

```go
// INSECURE - Path traversal vulnerable
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    http.ServeFile(w, r, filepath.Join("uploads", filename))
}

// SECURE - Validate path is within allowed directory
func serveFile(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")

    // Clean the path
    cleanPath := filepath.Clean(filename)

    // Reject paths that try to traverse
    if strings.Contains(cleanPath, "..") {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    basePath, _ := filepath.Abs("uploads")
    fullPath := filepath.Join(basePath, cleanPath)
    absPath, err := filepath.Abs(fullPath)
    if err != nil {
        http.Error(w, "Invalid path", http.StatusBadRequest)
        return
    }

    // Verify the absolute path is within base directory
    if !strings.HasPrefix(absPath, basePath+string(os.PathSeparator)) {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }

    http.ServeFile(w, r, absPath)
}

// Gin framework
func serveFile(c *gin.Context) {
    filename := c.Param("filename")

    basePath, _ := filepath.Abs("./uploads")
    requestedPath := filepath.Join(basePath, filepath.Clean(filename))
    absPath, _ := filepath.Abs(requestedPath)

    if !strings.HasPrefix(absPath, basePath+string(os.PathSeparator)) {
        c.AbortWithStatus(http.StatusForbidden)
        return
    }

    c.File(absPath)
}
```

### XSS Prevention

**Use html/template for HTML output (auto-escapes). Never use text/template for HTML.**

```go
// INSECURE - Using text/template for HTML (no auto-escaping)
import "text/template"

func handler(w http.ResponseWriter, r *http.Request) {
    tmpl := template.Must(template.New("page").Parse(`
        <div>Hello, {{.Name}}</div>
    `))
    tmpl.Execute(w, data)  // XSS vulnerable
}

// SECURE - Use html/template (auto-escapes)
import "html/template"

func handler(w http.ResponseWriter, r *http.Request) {
    tmpl := template.Must(template.New("page").Parse(`
        <div>Hello, {{.Name}}</div>
    `))
    tmpl.Execute(w, data)  // Auto-escaped
}

// INSECURE - Bypassing escaping with template.HTML
name := template.HTML(userInput)  // Dangerous if userInput is untrusted

// SECURE - Only use template.HTML for trusted, pre-sanitized content
import "github.com/microcosm-cc/bluemonday"

func sanitizeHTML(input string) template.HTML {
    p := bluemonday.UGCPolicy()
    clean := p.Sanitize(input)
    return template.HTML(clean)
}

// JSON API responses (no XSS concern for JSON, but set correct content-type)
func apiHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(data)
}
```

### Password Hashing

**Use bcrypt or Argon2 for password hashing.**

```go
// INSECURE - MD5/SHA hashing
import "crypto/md5"
hash := md5.Sum([]byte(password))

// INSECURE - SHA256 without proper KDF
import "crypto/sha256"
hash := sha256.Sum256([]byte(password))

// SECURE - bcrypt
import "golang.org/x/crypto/bcrypt"

func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(bytes), err
}

func verifyPassword(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// SECURE - Argon2id (recommended for new applications)
import "golang.org/x/crypto/argon2"

type Argon2Params struct {
    Memory      uint32
    Iterations  uint32
    Parallelism uint8
    SaltLength  uint32
    KeyLength   uint32
}

var DefaultParams = Argon2Params{
    Memory:      64 * 1024,  // 64 MB
    Iterations:  3,
    Parallelism: 2,
    SaltLength:  16,
    KeyLength:   32,
}

func hashPassword(password string) (string, error) {
    salt := make([]byte, DefaultParams.SaltLength)
    if _, err := rand.Read(salt); err != nil {
        return "", err
    }

    hash := argon2.IDKey(
        []byte(password),
        salt,
        DefaultParams.Iterations,
        DefaultParams.Memory,
        DefaultParams.Parallelism,
        DefaultParams.KeyLength,
    )

    // Encode salt and hash together
    return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
        argon2.Version,
        DefaultParams.Memory,
        DefaultParams.Iterations,
        DefaultParams.Parallelism,
        base64.RawStdEncoding.EncodeToString(salt),
        base64.RawStdEncoding.EncodeToString(hash),
    ), nil
}
```

### Cryptography Best Practices

**Use crypto/rand for random values. Use modern algorithms.**

```go
// INSECURE - math/rand is predictable
import "math/rand"
token := rand.Intn(1000000)

// SECURE - crypto/rand for secure random
import "crypto/rand"

func generateToken(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return hex.EncodeToString(bytes), nil
}

// SECURE - Generate random int
func secureRandomInt(max int64) (int64, error) {
    n, err := rand.Int(rand.Reader, big.NewInt(max))
    if err != nil {
        return 0, err
    }
    return n.Int64(), nil
}

// SECURE - AES-GCM encryption
import "crypto/aes"
import "crypto/cipher"

func encrypt(plaintext, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, err
    }

    return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext too short")
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return gcm.Open(nil, nonce, ciphertext, nil)
}
```

### Input Validation

**Validate all input with explicit checks or validation libraries.**

```go
import "github.com/go-playground/validator/v10"

var validate = validator.New()

type CreateUserRequest struct {
    Username string `json:"username" validate:"required,min=3,max=30,alphanum"`
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required,min=12"`
    Age      int    `json:"age" validate:"omitempty,gte=0,lte=150"`
}

func createUser(c *gin.Context) {
    var req CreateUserRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
        return
    }

    if err := validate.Struct(req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // Process validated input
}

// Custom validation
func init() {
    validate.RegisterValidation("safe_string", func(fl validator.FieldLevel) bool {
        value := fl.Field().String()
        // Only allow alphanumeric, underscore, dash
        return regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`).MatchString(value)
    })
}
```

### JWT Security

**Use explicit algorithm verification.**

```go
import "github.com/golang-jwt/jwt/v5"

// INSECURE - Not verifying algorithm
token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return secretKey, nil
})

// SECURE - Verify expected algorithm
func validateToken(tokenString string, secretKey []byte) (*jwt.Token, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Verify signing method
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return secretKey, nil
    })

    if err != nil {
        return nil, err
    }

    if !token.Valid {
        return nil, errors.New("invalid token")
    }

    return token, nil
}

// SECURE - Creating tokens with proper claims
func createToken(userID string, secretKey []byte) (string, error) {
    claims := jwt.MapClaims{
        "user_id": userID,
        "exp":     time.Now().Add(15 * time.Minute).Unix(),  // Short expiry
        "iat":     time.Now().Unix(),
        "iss":     "myapp",
        "aud":     "myapp-users",
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(secretKey)
}
```

### CORS Configuration

**Configure CORS explicitly, never allow all origins in production.**

```go
// INSECURE - Allow all origins
c.Writer.Header().Set("Access-Control-Allow-Origin", "*")

// SECURE - Explicit origin whitelist
func corsMiddleware() gin.HandlerFunc {
    allowedOrigins := map[string]bool{
        "https://example.com":     true,
        "https://www.example.com": true,
    }

    return func(c *gin.Context) {
        origin := c.Request.Header.Get("Origin")

        if allowedOrigins[origin] {
            c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
            c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
            c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
            c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
            c.Writer.Header().Set("Access-Control-Max-Age", "86400")
        }

        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(http.StatusNoContent)
            return
        }

        c.Next()
    }
}
```

### Security Headers

**Set security headers on all responses.**

```go
func securityHeadersMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
        c.Writer.Header().Set("X-Frame-Options", "DENY")
        c.Writer.Header().Set("X-XSS-Protection", "0")  // Disabled, CSP preferred
        c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        c.Writer.Header().Set("Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'")
        c.Writer.Header().Set("Strict-Transport-Security",
            "max-age=31536000; includeSubDomains")

        c.Next()
    }
}

// Standard net/http
func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        // ... other headers
        next.ServeHTTP(w, r)
    })
}
```

### Rate Limiting

**Implement rate limiting to prevent abuse.**

```go
import "golang.org/x/time/rate"

type RateLimiter struct {
    limiters map[string]*rate.Limiter
    mu       sync.Mutex
    rate     rate.Limit
    burst    int
}

func NewRateLimiter(r rate.Limit, burst int) *RateLimiter {
    return &RateLimiter{
        limiters: make(map[string]*rate.Limiter),
        rate:     r,
        burst:    burst,
    }
}

func (rl *RateLimiter) GetLimiter(key string) *rate.Limiter {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    limiter, exists := rl.limiters[key]
    if !exists {
        limiter = rate.NewLimiter(rl.rate, rl.burst)
        rl.limiters[key] = limiter
    }

    return limiter
}

func rateLimitMiddleware(rl *RateLimiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        ip := c.ClientIP()
        limiter := rl.GetLimiter(ip)

        if !limiter.Allow() {
            c.AbortWithStatusJSON(http.StatusTooManyRequests,
                gin.H{"error": "Rate limit exceeded"})
            return
        }

        c.Next()
    }
}
```

## Security Checklist

- [ ] All SQL uses parameterized queries
- [ ] No exec.Command with shell interpolation
- [ ] File paths validated against base directory
- [ ] html/template used for HTML (not text/template)
- [ ] Passwords hashed with bcrypt or Argon2
- [ ] crypto/rand used for random values
- [ ] JWT algorithm explicitly verified
- [ ] CORS configured with explicit origins
- [ ] Security headers set on all responses
- [ ] Rate limiting implemented
- [ ] Input validation on all endpoints

## Anti-Patterns to Flag

1. **fmt.Sprintf in SQL** - `fmt.Sprintf("WHERE id = %s", id)`
2. **exec.Command with shell** - `exec.Command("sh", "-c", cmd)`
3. **math/rand for security** - Use crypto/rand instead
4. **text/template for HTML** - XSS vulnerability
5. **MD5/SHA for passwords** - Use bcrypt/Argon2
6. **JWT without algorithm check** - Algorithm confusion attack
7. **CORS Allow-Origin: *** - Open to all origins
8. **filepath.Join without validation** - Path traversal
9. **template.HTML with user input** - XSS via bypass
10. **Hardcoded secrets** - `secretKey := "hardcoded"`
