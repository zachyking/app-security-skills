---
name: secure-java
description: Java security for Spring Boot - SQL injection, deserialization, XXE, broken access control. Use when writing Java code.
---

# secure-java

Security patterns for Java applications, with focus on Spring Boot and enterprise frameworks.

## When to Use

- Writing Java code for web applications
- Using Spring Boot, Spring Security, or Spring MVC
- Building REST APIs in Java
- Working with JPA/Hibernate or JDBC
- Implementing authentication/authorization in Java
- Processing XML, JSON, or serialized data

## Instructions

### SQL Injection Prevention

**Always use parameterized queries or JPA named parameters.**

```java
// INSECURE - SQL Injection vulnerable
@Repository
public class UserRepository {
    public User findByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        return jdbcTemplate.queryForObject(sql, new UserRowMapper());
    }
}

// SECURE - Parameterized query with JdbcTemplate
@Repository
public class UserRepository {
    public User findByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        return jdbcTemplate.queryForObject(sql, new UserRowMapper(), username);
    }
}

// SECURE - JPA with named parameters
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.username = :username")
    User findByUsername(@Param("username") String username);
}

// SECURE - Spring Data JPA derived query (auto-parameterized)
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
```

### Broken Access Control

**Implement authorization checks at the method level, not just URL patterns.**

```java
// INSECURE - No ownership check
@GetMapping("/api/documents/{id}")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id).orElseThrow();
}

// SECURE - Ownership verification
@GetMapping("/api/documents/{id}")
@PreAuthorize("isAuthenticated()")
public Document getDocument(@PathVariable Long id, Authentication auth) {
    Document doc = documentRepository.findById(id)
        .orElseThrow(() -> new ResourceNotFoundException("Document not found"));

    if (!doc.getOwnerId().equals(auth.getName())) {
        throw new AccessDeniedException("Not authorized to access this document");
    }
    return doc;
}

// SECURE - Using Spring Security expression
@GetMapping("/api/documents/{id}")
@PostAuthorize("returnObject.ownerId == authentication.name")
public Document getDocument(@PathVariable Long id) {
    return documentRepository.findById(id).orElseThrow();
}
```

**Configure method-level security:**
```java
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().denyByDefault()  // Deny by default
            );
        return http.build();
    }
}
```

### Deserialization Vulnerabilities

**Never deserialize untrusted data. Use safe alternatives.**

```java
// INSECURE - Arbitrary object deserialization
@PostMapping("/api/import")
public void importData(@RequestBody byte[] data) {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    Object obj = ois.readObject();  // RCE vulnerability
}

// SECURE - Use JSON with explicit types
@PostMapping("/api/import")
public void importData(@RequestBody ImportRequest request) {
    // Jackson automatically deserializes to known type
    processImport(request);
}

// If you MUST use Java serialization, use filtering
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.myapp.model.*;!*"  // Only allow specific packages
);
ObjectInputStream ois = new ObjectInputStream(input);
ois.setObjectInputFilter(filter);
```

**Configure Jackson securely:**
```java
@Configuration
public class JacksonConfig {

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();

        // Disable dangerous features
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        mapper.deactivateDefaultTyping();  // Prevent polymorphic deserialization

        // Don't accept unknown properties that could be injection attempts
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);

        return mapper;
    }
}
```

### XML External Entity (XXE) Prevention

**Disable external entity processing in all XML parsers.**

```java
// INSECURE - XXE vulnerable
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(inputStream);  // XXE possible

// SECURE - Disable external entities
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
DocumentBuilder builder = factory.newDocumentBuilder();
```

**Secure SAX parser:**
```java
SAXParserFactory factory = SAXParserFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

### Password Storage

**Use BCrypt or Argon2 with Spring Security.**

```java
// INSECURE - MD5/SHA hashing
String hash = DigestUtils.md5Hex(password);

// INSECURE - Plain SHA-256
MessageDigest md = MessageDigest.getInstance("SHA-256");
byte[] hash = md.digest(password.getBytes());

// SECURE - BCrypt with Spring Security
@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);  // Cost factor 12
    }
}

@Service
public class UserService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    public void createUser(String username, String password) {
        String hashedPassword = passwordEncoder.encode(password);
        // Store hashedPassword in database
    }

    public boolean verifyPassword(String rawPassword, String storedHash) {
        return passwordEncoder.matches(rawPassword, storedHash);
    }
}

// SECURE - Argon2 (stronger, recommended for new applications)
@Bean
public PasswordEncoder passwordEncoder() {
    return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
}
```

### Session Management

**Configure secure session handling in Spring Security.**

```java
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)  // Prevent session fixation via multiple logins
                .maxSessionsPreventsLogin(true)
                .sessionRegistry(sessionRegistry())
            )
            .sessionManagement(session -> session
                .sessionFixation().newSession()  // Create new session on auth
            );
        return http.build();
    }
}

// Secure cookie configuration in application.properties
// server.servlet.session.cookie.secure=true
// server.servlet.session.cookie.http-only=true
// server.servlet.session.cookie.same-site=lax
// server.servlet.session.timeout=30m
```

### CSRF Protection

**Enable CSRF protection for stateful applications.**

```java
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // For traditional web apps with sessions
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            );

        // For stateless REST APIs with JWT, CSRF can be disabled
        // http.csrf(csrf -> csrf.disable());

        return http.build();
    }
}
```

### Input Validation

**Use Bean Validation (JSR-380) for all input.**

```java
public class CreateUserRequest {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be 3-50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, underscore")
    private String username;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 12, message = "Password must be at least 12 characters")
    private String password;

    // Getters and setters
}

@RestController
public class UserController {

    @PostMapping("/api/users")
    public ResponseEntity<User> createUser(@Valid @RequestBody CreateUserRequest request) {
        // Request is validated before reaching here
        return ResponseEntity.ok(userService.createUser(request));
    }
}
```

### Path Traversal Prevention

**Validate and sanitize file paths.**

```java
// INSECURE - Path traversal vulnerable
@GetMapping("/files/{filename}")
public Resource getFile(@PathVariable String filename) {
    Path path = Paths.get("/uploads/" + filename);  // ../../../etc/passwd
    return new FileSystemResource(path);
}

// SECURE - Validate path is within allowed directory
@GetMapping("/files/{filename}")
public Resource getFile(@PathVariable String filename) {
    Path basePath = Paths.get("/uploads").toAbsolutePath().normalize();
    Path filePath = basePath.resolve(filename).normalize();

    // Ensure resolved path is within base directory
    if (!filePath.startsWith(basePath)) {
        throw new AccessDeniedException("Invalid file path");
    }

    if (!Files.exists(filePath)) {
        throw new ResourceNotFoundException("File not found");
    }

    return new FileSystemResource(filePath);
}
```

### Logging Security

**Never log sensitive data.**

```java
// INSECURE - Logging sensitive data
logger.info("User login attempt: username={}, password={}", username, password);
logger.debug("Processing credit card: {}", creditCardNumber);

// SECURE - Redact sensitive information
logger.info("User login attempt: username={}", username);
logger.debug("Processing credit card ending in: {}", creditCardNumber.substring(creditCardNumber.length() - 4));

// Use structured logging with masking
@Configuration
public class LoggingConfig {
    // Configure Logback/Log4j2 to mask patterns:
    // - Credit card numbers
    // - SSNs
    // - Passwords
    // - API keys
}
```

### Security Headers

**Configure security headers in Spring.**

```java
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'; script-src 'self'; style-src 'self'")
                )
                .frameOptions(frame -> frame.deny())
                .httpStrictTransportSecurity(hsts -> hsts
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true)
                )
                .xssProtection(xss -> xss.disable())  // Modern browsers don't need this
                .contentTypeOptions(contentType -> {})  // X-Content-Type-Options: nosniff
            );
        return http.build();
    }
}
```

### Secure Dependencies

**Common vulnerable dependencies to watch:**

| Dependency | Vulnerability | Fix |
|------------|--------------|-----|
| Log4j < 2.17.1 | Log4Shell RCE | Update to >= 2.17.1 |
| Spring Framework < 5.3.18 | Spring4Shell | Update to >= 5.3.18 |
| Jackson < 2.13.2 | Deserialization issues | Update to latest |
| Apache Commons Text < 1.10 | Text4Shell | Update to >= 1.10 |
| Hibernate < 5.4.24 | SQL injection in certain cases | Update to latest |
| SnakeYAML < 2.0 | Arbitrary code execution | Update to >= 2.0 |

```xml
<!-- Maven: Check for vulnerable dependencies -->
<plugin>
    <groupId>org.owasp</groupId>
    <artifactId>dependency-check-maven</artifactId>
    <version>8.4.0</version>
    <executions>
        <execution>
            <goals>
                <goal>check</goal>
            </goals>
        </execution>
    </executions>
</plugin>
```

## Security Checklist

- [ ] All SQL queries use parameterized statements or JPA
- [ ] Authorization checked at method level, not just URL
- [ ] No Java deserialization of untrusted data
- [ ] XML parsers have external entities disabled
- [ ] Passwords hashed with BCrypt or Argon2
- [ ] Sessions configured with secure cookies
- [ ] CSRF protection enabled for stateful apps
- [ ] All input validated with Bean Validation
- [ ] File paths validated against traversal
- [ ] Sensitive data never logged
- [ ] Security headers configured
- [ ] Dependencies checked for vulnerabilities

## Anti-Patterns to Flag

1. **String concatenation in SQL** - `"SELECT * FROM users WHERE id = " + id`
2. **ObjectInputStream on untrusted data** - Deserialization RCE
3. **XML parsing without disabling DTD** - XXE attacks
4. **MD5/SHA1 for passwords** - Use BCrypt/Argon2
5. **Missing @PreAuthorize** - No method-level security
6. **CSRF disabled without JWT** - Cross-site request forgery
7. **Log4j without upgrade** - Log4Shell vulnerability
8. **Unsanitized file paths** - Path traversal
9. **Sensitive data in logs** - Information disclosure
10. **Jackson default typing enabled** - Deserialization gadgets
