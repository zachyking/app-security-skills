---
name: secure-dotnet
description: C#/.NET security for ASP.NET Core - SQL injection, path traversal, XSS, CSRF, Entity Framework security. Use when writing C#/.NET code.
---

# secure-dotnet

Security patterns for C# and ASP.NET Core applications.

## When to Use

- Writing C# web applications
- Using ASP.NET Core, Blazor, or ASP.NET MVC
- Building REST APIs with .NET
- Working with Entity Framework Core or ADO.NET
- Implementing authentication/authorization in .NET
- Processing XML, JSON, or user-uploaded files

## Instructions

### SQL Injection Prevention

**Always use parameterized queries or Entity Framework.**

```csharp
// INSECURE - SQL Injection vulnerable
public User GetUser(string username)
{
    var query = $"SELECT * FROM Users WHERE Username = '{username}'";
    return _context.Users.FromSqlRaw(query).FirstOrDefault();
}

// INSECURE - String concatenation
var query = "SELECT * FROM Users WHERE Id = " + userId;

// SECURE - Parameterized FromSqlRaw
public User GetUser(string username)
{
    return _context.Users
        .FromSqlRaw("SELECT * FROM Users WHERE Username = {0}", username)
        .FirstOrDefault();
}

// SECURE - FromSqlInterpolated (auto-parameterized)
public User GetUser(string username)
{
    return _context.Users
        .FromSqlInterpolated($"SELECT * FROM Users WHERE Username = {username}")
        .FirstOrDefault();
}

// SECURE - LINQ (always parameterized)
public User GetUser(string username)
{
    return _context.Users.FirstOrDefault(u => u.Username == username);
}

// SECURE - ADO.NET with parameters
using var command = new SqlCommand("SELECT * FROM Users WHERE Username = @username", connection);
command.Parameters.AddWithValue("@username", username);
```

### Path Traversal Prevention

**Validate file paths against allowed directories.**

```csharp
// INSECURE - Path traversal vulnerable
[HttpGet("files/{filename}")]
public IActionResult GetFile(string filename)
{
    var path = Path.Combine("uploads", filename);
    return PhysicalFile(path, "application/octet-stream");
}

// SECURE - Validate path is within allowed directory
[HttpGet("files/{filename}")]
public IActionResult GetFile(string filename)
{
    var basePath = Path.GetFullPath("uploads");
    var fullPath = Path.GetFullPath(Path.Combine(basePath, filename));

    // Ensure the path is within the base directory
    if (!fullPath.StartsWith(basePath + Path.DirectorySeparatorChar))
    {
        return Forbid();
    }

    if (!System.IO.File.Exists(fullPath))
    {
        return NotFound();
    }

    return PhysicalFile(fullPath, "application/octet-stream");
}

// SECURE - Using Path.GetFileName to strip directory components
[HttpGet("files/{filename}")]
public IActionResult GetFile(string filename)
{
    // GetFileName strips any directory path, preventing traversal
    var safeFilename = Path.GetFileName(filename);
    var fullPath = Path.Combine("uploads", safeFilename);

    if (!System.IO.File.Exists(fullPath))
    {
        return NotFound();
    }

    return PhysicalFile(fullPath, "application/octet-stream");
}
```

### XSS Prevention

**Use Razor encoding and avoid Html.Raw with user input.**

```csharp
// Razor auto-escapes by default - SECURE
<div>@Model.UserInput</div>

// INSECURE - Html.Raw bypasses encoding
<div>@Html.Raw(Model.UserInput)</div>

// SECURE - If HTML is needed, sanitize first
@using Ganss.Xss;
@{
    var sanitizer = new HtmlSanitizer();
    var clean = sanitizer.Sanitize(Model.UserInput);
}
<div>@Html.Raw(clean)</div>

// Configure HtmlSanitizer
var sanitizer = new HtmlSanitizer();
sanitizer.AllowedTags.Clear();
sanitizer.AllowedTags.Add("p");
sanitizer.AllowedTags.Add("br");
sanitizer.AllowedTags.Add("strong");
sanitizer.AllowedTags.Add("em");
sanitizer.AllowedAttributes.Clear();

// JavaScript encoding for JS contexts
<script>
    var userName = '@Html.Raw(JavaScriptEncoder.Default.Encode(Model.UserName))';
</script>
```

### Authorization

**Implement authorization at controller and action levels.**

```csharp
// INSECURE - No authorization check
[HttpGet("documents/{id}")]
public async Task<IActionResult> GetDocument(int id)
{
    var document = await _context.Documents.FindAsync(id);
    return Ok(document);
}

// SECURE - Ownership check
[Authorize]
[HttpGet("documents/{id}")]
public async Task<IActionResult> GetDocument(int id)
{
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    var document = await _context.Documents.FindAsync(id);

    if (document == null)
        return NotFound();

    if (document.OwnerId != userId)
        return Forbid();

    return Ok(document);
}

// SECURE - Policy-based authorization
[Authorize(Policy = "DocumentOwner")]
[HttpGet("documents/{id}")]
public async Task<IActionResult> GetDocument(int id)
{
    var document = await _context.Documents.FindAsync(id);
    return Ok(document);
}

// Configure policy in Startup/Program.cs
services.AddAuthorization(options =>
{
    options.AddPolicy("DocumentOwner", policy =>
        policy.Requirements.Add(new DocumentOwnerRequirement()));
});

// Resource-based authorization handler
public class DocumentOwnerHandler : AuthorizationHandler<DocumentOwnerRequirement, Document>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        DocumentOwnerRequirement requirement,
        Document resource)
    {
        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (resource.OwnerId == userId)
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}
```

### Password Storage

**Use ASP.NET Core Identity or proper password hashing.**

```csharp
// INSECURE - Weak hashing
using var md5 = MD5.Create();
var hash = Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));

// INSECURE - SHA256 without salt/iterations
using var sha = SHA256.Create();
var hash = Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(password)));

// SECURE - ASP.NET Core Identity (uses PBKDF2 by default)
public class AccountController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;

    public async Task<IActionResult> Register(RegisterModel model)
    {
        var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);
        // Password automatically hashed by Identity
    }
}

// SECURE - Manual password hashing with Rfc2898DeriveBytes
public static class PasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 100000;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            HashSize);

        return $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string hashedPassword)
    {
        var parts = hashedPassword.Split('.');
        var salt = Convert.FromBase64String(parts[0]);
        var hash = Convert.FromBase64String(parts[1]);

        var testHash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            HashSize);

        return CryptographicOperations.FixedTimeEquals(hash, testHash);
    }
}
```

### CSRF Protection

**Enable anti-forgery tokens for forms.**

```csharp
// Startup/Program.cs - Configure anti-forgery
services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});

services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// In Razor views
<form method="post">
    @Html.AntiForgeryToken()
    <!-- or -->
    <input name="__RequestVerificationToken" type="hidden" value="@Antiforgery.GetAndStoreTokens(Context).RequestToken" />
</form>

// For AJAX requests
[HttpPost]
[ValidateAntiForgeryToken]
public IActionResult UpdateProfile(ProfileModel model)
{
    // Token validated automatically
}

// JavaScript: Include token in AJAX headers
$.ajaxSetup({
    headers: {
        'X-CSRF-TOKEN': $('input[name="__RequestVerificationToken"]').val()
    }
});
```

### Input Validation

**Use Data Annotations and FluentValidation.**

```csharp
// Data Annotations
public class CreateUserRequest
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(30, MinimumLength = 3)]
    [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Invalid characters")]
    public string Username { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [MinLength(12, ErrorMessage = "Password must be at least 12 characters")]
    public string Password { get; set; }
}

[HttpPost]
public IActionResult CreateUser([FromBody] CreateUserRequest request)
{
    if (!ModelState.IsValid)
    {
        return BadRequest(ModelState);
    }
    // Process validated input
}

// FluentValidation (more powerful)
public class CreateUserRequestValidator : AbstractValidator<CreateUserRequest>
{
    public CreateUserRequestValidator()
    {
        RuleFor(x => x.Username)
            .NotEmpty()
            .Length(3, 30)
            .Matches(@"^[a-zA-Z0-9_]+$")
            .WithMessage("Username can only contain letters, numbers, and underscore");

        RuleFor(x => x.Email)
            .NotEmpty()
            .EmailAddress();

        RuleFor(x => x.Password)
            .NotEmpty()
            .MinimumLength(12)
            .Matches(@"[A-Z]").WithMessage("Password must contain uppercase")
            .Matches(@"[a-z]").WithMessage("Password must contain lowercase")
            .Matches(@"\d").WithMessage("Password must contain digit");
    }
}
```

### XML External Entity (XXE) Prevention

**Disable DTD processing in XML parsers.**

```csharp
// INSECURE - XXE vulnerable
var doc = new XmlDocument();
doc.Load(xmlStream);  // DTD processing enabled by default in older .NET

// SECURE - Disable DTD processing
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null
};

using var reader = XmlReader.Create(xmlStream, settings);
var doc = new XmlDocument();
doc.Load(reader);

// SECURE - For XDocument
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit
};
using var reader = XmlReader.Create(xmlStream, settings);
var xdoc = XDocument.Load(reader);
```

### Security Headers

**Configure security headers in middleware.**

```csharp
// Program.cs or Startup.cs
app.UseHsts();
app.UseHttpsRedirection();

// Custom security headers middleware
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Add("X-Frame-Options", "DENY");
    context.Response.Headers.Add("X-XSS-Protection", "0");  // Disabled, CSP preferred
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Add("Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;");
    context.Response.Headers.Add("Permissions-Policy",
        "geolocation=(), microphone=(), camera=()");

    await next();
});

// Or use NWebsec package
app.UseXContentTypeOptions();
app.UseXfo(options => options.Deny());
app.UseCsp(options => options
    .DefaultSources(s => s.Self())
    .ScriptSources(s => s.Self())
    .StyleSources(s => s.Self()));
```

### Secure Configuration

**Store secrets securely, not in appsettings.json.**

```csharp
// INSECURE - Secrets in appsettings.json
{
    "ConnectionStrings": {
        "Default": "Server=...;Password=secret123"
    },
    "ApiKey": "sk-1234567890"
}

// SECURE - Use Secret Manager (development)
// dotnet user-secrets set "ApiKey" "sk-1234567890"
var apiKey = Configuration["ApiKey"];

// SECURE - Use environment variables (production)
var connectionString = Environment.GetEnvironmentVariable("DB_CONNECTION_STRING");

// SECURE - Use Azure Key Vault or AWS Secrets Manager
builder.Configuration.AddAzureKeyVault(
    new Uri($"https://{keyVaultName}.vault.azure.net/"),
    new DefaultAzureCredential());

// Program.cs configuration
var builder = WebApplication.CreateBuilder(args);

if (builder.Environment.IsDevelopment())
{
    builder.Configuration.AddUserSecrets<Program>();
}
else
{
    builder.Configuration.AddEnvironmentVariables();
    builder.Configuration.AddAzureKeyVault(/* ... */);
}
```

### Logging Security

**Never log sensitive data.**

```csharp
// INSECURE - Logging sensitive data
_logger.LogInformation("User login: {Username}, Password: {Password}", username, password);
_logger.LogDebug("Processing card: {CardNumber}", cardNumber);

// SECURE - Exclude sensitive data
_logger.LogInformation("User login attempt: {Username}", username);
_logger.LogDebug("Processing card ending in: {LastFour}", cardNumber[^4..]);

// Configure Serilog to mask sensitive fields
Log.Logger = new LoggerConfiguration()
    .Destructure.ByTransforming<UserLoginRequest>(r =>
        new { r.Username, Password = "***REDACTED***" })
    .CreateLogger();

// Use structured logging with explicit fields
_logger.LogInformation("User {UserId} accessed document {DocumentId}",
    userId, documentId);
```

## Security Checklist

- [ ] All SQL uses parameterized queries or EF LINQ
- [ ] File paths validated against base directory
- [ ] No Html.Raw with unsanitized user input
- [ ] Authorization on all sensitive endpoints
- [ ] Passwords use Identity or PBKDF2/Argon2
- [ ] Anti-forgery tokens on all forms
- [ ] All input validated with Data Annotations/FluentValidation
- [ ] XML parsers have DTD processing disabled
- [ ] Security headers configured
- [ ] Secrets not in appsettings.json
- [ ] Sensitive data not logged

## Anti-Patterns to Flag

1. **String interpolation in SQL** - `FromSqlRaw($"... WHERE id = {id}")`
2. **Path.Combine without validation** - Path traversal risk
3. **Html.Raw with user input** - XSS vulnerability
4. **Missing [Authorize] attribute** - Unauthenticated access
5. **MD5/SHA for passwords** - Weak hashing
6. **Missing [ValidateAntiForgeryToken]** - CSRF vulnerability
7. **DtdProcessing not disabled** - XXE vulnerability
8. **Secrets in appsettings.json** - Exposed credentials
9. **Missing input validation** - Injection/logic flaws
10. **Logging passwords/tokens** - Information disclosure
