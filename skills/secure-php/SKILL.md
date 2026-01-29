---
name: secure-php
description: PHP security for Laravel, Symfony - SQL injection, command injection, object injection, file uploads. Use when writing PHP code.
---

# secure-php

Security patterns for PHP applications including Laravel and Symfony frameworks.

## When to Use

- Writing PHP web applications
- Using Laravel, Symfony, or other PHP frameworks
- Building REST APIs in PHP
- Working with databases (PDO, Eloquent, Doctrine)
- Processing user input or file uploads
- Implementing authentication/authorization in PHP

## Instructions

### SQL Injection Prevention

**Always use prepared statements or ORM query builders.**

```php
// INSECURE - SQL Injection vulnerable
$username = $_GET['username'];
$query = "SELECT * FROM users WHERE username = '$username'";
$result = mysqli_query($conn, $query);

// INSECURE - Even with mysqli_real_escape_string (still risky)
$username = mysqli_real_escape_string($conn, $_GET['username']);
$query = "SELECT * FROM users WHERE username = '$username'";

// SECURE - PDO prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
$user = $stmt->fetch();

// SECURE - PDO with named parameters
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute(['username' => $username]);

// SECURE - Laravel Eloquent
$user = User::where('username', $username)->first();

// SECURE - Laravel Query Builder
$user = DB::table('users')->where('username', $username)->first();

// SECURE - Symfony Doctrine
$user = $entityManager->getRepository(User::class)
    ->findOneBy(['username' => $username]);

// SECURE - Doctrine QueryBuilder
$qb = $entityManager->createQueryBuilder();
$qb->select('u')
   ->from('App\Entity\User', 'u')
   ->where('u.username = :username')
   ->setParameter('username', $username);
```

### Command Injection Prevention

**Avoid shell functions with user input; use escapeshellarg if necessary.**

```php
// INSECURE - Command injection
$filename = $_GET['file'];
exec("cat $filename");  // ; rm -rf /

// INSECURE - Even with escapeshellcmd (bypasses possible)
exec(escapeshellcmd("cat $filename"));

// SECURE - escapeshellarg for arguments
$filename = escapeshellarg($_GET['file']);
exec("cat $filename");  // Quotes the argument

// SECURE - Avoid shell entirely when possible
$content = file_get_contents($validatedPath);

// SECURE - Use specific functions instead of shell
// Instead of: exec("convert $input $output")
// Use: Imagick extension
$image = new Imagick($validatedInputPath);
$image->writeImage($outputPath);

// If shell is required, validate input strictly
function processFile(string $filename): string
{
    // Whitelist allowed characters
    if (!preg_match('/^[a-zA-Z0-9_\-\.]+$/', $filename)) {
        throw new InvalidArgumentException('Invalid filename');
    }

    // Verify file exists in expected directory
    $basePath = realpath('/uploads');
    $fullPath = realpath('/uploads/' . $filename);

    if ($fullPath === false || strpos($fullPath, $basePath) !== 0) {
        throw new InvalidArgumentException('Invalid path');
    }

    return shell_exec('file ' . escapeshellarg($fullPath));
}
```

### XSS Prevention

**Always escape output; use framework templating.**

```php
// INSECURE - Direct output
echo "<div>Hello, " . $_GET['name'] . "</div>";

// INSECURE - Even inside attributes
echo "<input value='" . $_GET['value'] . "'>";

// SECURE - Use htmlspecialchars
echo "<div>Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</div>";

// SECURE - Create an escape helper
function e(string $string): string
{
    return htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
echo "<div>Hello, " . e($name) . "</div>";

// SECURE - Laravel Blade (auto-escapes)
// {{ $name }} - Escaped
// {!! $name !!} - DANGEROUS: Unescaped, avoid with user data

// SECURE - Symfony Twig (auto-escapes)
// {{ name }} - Escaped
// {{ name|raw }} - DANGEROUS: Unescaped

// For HTML content, use a sanitizer
use HTMLPurifier;

$config = HTMLPurifier_Config::createDefault();
$config->set('HTML.Allowed', 'p,br,strong,em,a[href]');
$purifier = new HTMLPurifier($config);
$clean = $purifier->purify($userHtml);
```

### CSRF Protection

**Use CSRF tokens for all state-changing requests.**

```php
// Manual CSRF protection
session_start();

// Generate token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// In form
echo '<input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';

// Validate on submission
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
    die('CSRF token validation failed');
}

// Laravel - Automatic with @csrf directive
<form method="POST" action="/profile">
    @csrf
    <!-- form fields -->
</form>

// Symfony - Form component handles automatically
{{ form_start(form) }}
    {# CSRF token included automatically #}
{{ form_end(form) }}

// For AJAX in Laravel
$.ajaxSetup({
    headers: {
        'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
    }
});
```

### Password Storage

**Use password_hash with PASSWORD_DEFAULT or PASSWORD_ARGON2ID.**

```php
// INSECURE - MD5/SHA1
$hash = md5($password);
$hash = sha1($password);

// INSECURE - Even with salt (still too fast)
$hash = md5($password . $salt);

// SECURE - password_hash (uses bcrypt by default)
$hash = password_hash($password, PASSWORD_DEFAULT);

// SECURE - Argon2id (recommended for new applications)
$hash = password_hash($password, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,  // 64 MB
    'time_cost' => 4,
    'threads' => 3
]);

// Verify password
if (password_verify($inputPassword, $storedHash)) {
    // Password correct
    // Check if rehash needed (algorithm upgraded)
    if (password_needs_rehash($storedHash, PASSWORD_DEFAULT)) {
        $newHash = password_hash($inputPassword, PASSWORD_DEFAULT);
        // Update stored hash
    }
}

// Laravel - Uses bcrypt by default
use Illuminate\Support\Facades\Hash;

$hash = Hash::make($password);
if (Hash::check($password, $hash)) {
    // Valid
}
```

### File Upload Security

**Validate file type, size, and store outside web root.**

```php
// INSECURE - Trusting user-provided filename and type
$filename = $_FILES['upload']['name'];
move_uploaded_file($_FILES['upload']['tmp_name'], "uploads/$filename");

// SECURE - Comprehensive file upload handling
function handleFileUpload(array $file): string
{
    $maxSize = 5 * 1024 * 1024; // 5 MB
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    $uploadDir = '/var/www/storage/uploads/'; // Outside web root

    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        throw new RuntimeException('Upload failed');
    }

    // Validate size
    if ($file['size'] > $maxSize) {
        throw new RuntimeException('File too large');
    }

    // Validate MIME type by content (not user-provided type)
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mimeType = $finfo->file($file['tmp_name']);
    if (!in_array($mimeType, $allowedTypes, true)) {
        throw new RuntimeException('Invalid file type');
    }

    // Generate random filename (don't trust user filename)
    $extension = match($mimeType) {
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/gif' => 'gif',
        default => throw new RuntimeException('Unknown type')
    };
    $newFilename = bin2hex(random_bytes(16)) . '.' . $extension;

    // Move to upload directory
    $destination = $uploadDir . $newFilename;
    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        throw new RuntimeException('Failed to move file');
    }

    return $newFilename;
}

// Laravel file upload
$request->validate([
    'file' => 'required|file|mimes:jpg,png,gif|max:5120'
]);

$path = $request->file('file')->store('uploads', 'private');
```

### Session Security

**Configure secure session settings.**

```php
// php.ini or runtime configuration
ini_set('session.cookie_httponly', 1);      // No JavaScript access
ini_set('session.cookie_secure', 1);        // HTTPS only
ini_set('session.cookie_samesite', 'Lax');  // CSRF protection
ini_set('session.use_strict_mode', 1);      // Reject uninitialized session IDs
ini_set('session.use_only_cookies', 1);     // Only accept cookies
ini_set('session.gc_maxlifetime', 3600);    // 1 hour expiry

// Regenerate session ID on privilege change
session_regenerate_id(true);  // true = delete old session

// Laravel session config (config/session.php)
return [
    'driver' => env('SESSION_DRIVER', 'file'),
    'lifetime' => 120, // minutes
    'expire_on_close' => false,
    'encrypt' => true,
    'cookie' => 'app_session',
    'path' => '/',
    'domain' => env('SESSION_DOMAIN'),
    'secure' => true,
    'http_only' => true,
    'same_site' => 'lax',
];
```

### Path Traversal Prevention

**Validate file paths against allowed directories.**

```php
// INSECURE - Path traversal vulnerable
$file = $_GET['file'];
include("templates/$file.php");  // ../../etc/passwd

// SECURE - Whitelist approach
$allowedTemplates = ['header', 'footer', 'sidebar'];
$template = $_GET['template'];
if (!in_array($template, $allowedTemplates, true)) {
    die('Invalid template');
}
include("templates/$template.php");

// SECURE - Path validation
function getSecurePath(string $basePath, string $userPath): string
{
    $basePath = realpath($basePath);
    $fullPath = realpath($basePath . '/' . $userPath);

    if ($fullPath === false || strpos($fullPath, $basePath) !== 0) {
        throw new RuntimeException('Invalid path');
    }

    return $fullPath;
}

// Usage
$path = getSecurePath('/var/www/files', $_GET['file']);
$content = file_get_contents($path);
```

### Object Injection Prevention

**Never unserialize untrusted data.**

```php
// INSECURE - Object injection vulnerability
$data = unserialize($_COOKIE['user_prefs']);
// Attacker can craft serialized objects with malicious __wakeup/__destruct

// SECURE - Use JSON instead
$data = json_decode($_COOKIE['user_prefs'], true);

// SECURE - If serialization needed, use signed data
function serializeSigned(mixed $data, string $key): string
{
    $serialized = serialize($data);
    $signature = hash_hmac('sha256', $serialized, $key);
    return base64_encode($signature . $serialized);
}

function unserializeSigned(string $data, string $key): mixed
{
    $decoded = base64_decode($data);
    $signature = substr($decoded, 0, 64);
    $serialized = substr($decoded, 64);

    if (!hash_equals(hash_hmac('sha256', $serialized, $key), $signature)) {
        throw new RuntimeException('Invalid signature');
    }

    // Only allow specific classes
    return unserialize($serialized, ['allowed_classes' => [SafeClass::class]]);
}

// Laravel - Use signed URLs/data
use Illuminate\Support\Facades\Crypt;
$encrypted = Crypt::encrypt($data);
$decrypted = Crypt::decrypt($encrypted);
```

### SQL Error Exposure

**Never display database errors to users.**

```php
// INSECURE - Exposes database structure
try {
    $stmt = $pdo->prepare($query);
    $stmt->execute();
} catch (PDOException $e) {
    echo "Error: " . $e->getMessage();  // Exposes SQL query
}

// SECURE - Log errors, show generic message
try {
    $stmt = $pdo->prepare($query);
    $stmt->execute();
} catch (PDOException $e) {
    error_log("Database error: " . $e->getMessage());
    throw new RuntimeException('An error occurred. Please try again.');
}

// Configure PDO for exceptions
$pdo = new PDO($dsn, $user, $pass, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => false,  // Use real prepared statements
]);

// Production error handling
if (getenv('APP_ENV') === 'production') {
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
}
```

### Laravel-Specific Security

```php
// config/app.php
'debug' => env('APP_DEBUG', false),  // false in production

// .env (never commit to version control)
APP_DEBUG=false
APP_KEY=base64:...  // Generate with: php artisan key:generate

// Mass assignment protection
class User extends Model
{
    // Only allow these fields to be mass-assigned
    protected $fillable = ['name', 'email'];

    // Or block specific fields
    protected $guarded = ['is_admin', 'role'];
}

// Middleware for authentication
Route::middleware(['auth'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
});

// Authorization with policies
// php artisan make:policy DocumentPolicy --model=Document
class DocumentPolicy
{
    public function view(User $user, Document $document): bool
    {
        return $user->id === $document->user_id;
    }
}

// Usage in controller
public function show(Document $document)
{
    $this->authorize('view', $document);
    return view('documents.show', compact('document'));
}

// Rate limiting
Route::middleware(['throttle:api'])->group(function () {
    Route::post('/login', [AuthController::class, 'login']);
});
```

### Symfony-Specific Security

```yaml
# config/packages/security.yaml
security:
    password_hashers:
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface:
            algorithm: auto  # Uses Argon2id when available

    firewalls:
        main:
            lazy: true
            provider: app_user_provider
            form_login:
                login_path: login
                check_path: login
                enable_csrf: true
            logout:
                path: logout

    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN }
        - { path: ^/profile, roles: ROLE_USER }
```

```php
// Controller authorization
#[IsGranted('ROLE_ADMIN')]
public function adminDashboard(): Response
{
    // ...
}

// Voter for fine-grained authorization
class DocumentVoter extends Voter
{
    protected function supports(string $attribute, mixed $subject): bool
    {
        return $subject instanceof Document;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $user = $token->getUser();
        return $subject->getOwner() === $user;
    }
}
```

## Security Checklist

- [ ] All SQL uses prepared statements or ORM
- [ ] No shell_exec/exec/system with user input
- [ ] All output escaped (htmlspecialchars or template engine)
- [ ] CSRF tokens on all forms
- [ ] Passwords use password_hash with PASSWORD_ARGON2ID
- [ ] File uploads validated by content, stored outside web root
- [ ] Secure session configuration
- [ ] File paths validated against traversal
- [ ] No unserialize on untrusted data
- [ ] Database errors not exposed to users
- [ ] debug=false in production

## Anti-Patterns to Flag

1. **Variables in SQL strings** - `"WHERE id = $id"`
2. **exec/shell_exec with user input** - Command injection
3. **echo without htmlspecialchars** - XSS vulnerability
4. **md5/sha1 for passwords** - Weak hashing
5. **unserialize on user data** - Object injection
6. **$_FILES['name'] trusted** - Path traversal
7. **display_errors in production** - Information disclosure
8. **Missing CSRF tokens** - Cross-site request forgery
9. **include with user input** - Local file inclusion
10. **$_GET/$_POST without validation** - Multiple vulnerabilities
