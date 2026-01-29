---
name: secure-mobile
description: Mobile security for iOS (Swift) and Android (Kotlin) - secure storage, certificate pinning, biometrics, WebView hardening. Use for mobile development.
---

# secure-mobile

Security patterns for iOS (Swift) and Android (Kotlin) mobile applications.

## When to Use

- Building iOS applications with Swift
- Building Android applications with Kotlin
- Implementing authentication in mobile apps
- Storing sensitive data locally
- Making network requests from mobile apps
- Handling user credentials or tokens
- Implementing biometric authentication

## Instructions

### Secure Data Storage

**Never store sensitive data in plain text. Use platform secure storage.**

#### iOS (Swift)

```swift
// INSECURE - UserDefaults is not encrypted
UserDefaults.standard.set(apiToken, forKey: "token")
UserDefaults.standard.set(password, forKey: "password")

// INSECURE - Writing to plain file
try password.write(toFile: path, atomically: true, encoding: .utf8)

// SECURE - Use Keychain for sensitive data
import Security

class KeychainHelper {
    static func save(key: String, data: Data) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        SecItemDelete(query as CFDictionary)  // Remove existing
        return SecItemAdd(query as CFDictionary, nil)
    }

    static func load(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    static func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// Usage
let tokenData = apiToken.data(using: .utf8)!
KeychainHelper.save(key: "api_token", data: tokenData)
```

#### Android (Kotlin)

```kotlin
// INSECURE - SharedPreferences is not encrypted by default
val prefs = getSharedPreferences("app_prefs", Context.MODE_PRIVATE)
prefs.edit().putString("token", apiToken).apply()

// INSECURE - Writing to plain file
File(filesDir, "password.txt").writeText(password)

// SECURE - Use EncryptedSharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SecureStorage(context: Context) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val securePrefs = EncryptedSharedPreferences.create(
        context,
        "secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveToken(token: String) {
        securePrefs.edit().putString("api_token", token).apply()
    }

    fun getToken(): String? {
        return securePrefs.getString("api_token", null)
    }

    fun deleteToken() {
        securePrefs.edit().remove("api_token").apply()
    }
}

// SECURE - Use Android Keystore for cryptographic keys
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator

class KeystoreHelper {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun generateKey(alias: String) {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )

        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)  // Require biometric
            .setUserAuthenticationValidityDurationSeconds(30)
            .build()

        keyGenerator.init(spec)
        keyGenerator.generateKey()
    }
}
```

### Certificate Pinning

**Pin certificates to prevent MitM attacks.**

#### iOS (Swift)

```swift
// Using URLSession with certificate pinning
class PinnedURLSessionDelegate: NSObject, URLSessionDelegate {
    let pinnedCertificates: [Data]

    init(pinnedCertificates: [Data]) {
        self.pinnedCertificates = pinnedCertificates
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Get server certificate
        guard let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let serverCertData = SecCertificateCopyData(serverCertificate) as Data

        // Check if server cert matches any pinned cert
        if pinnedCertificates.contains(serverCertData) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

// Using Alamofire with pinning
import Alamofire

let evaluators: [String: ServerTrustEvaluating] = [
    "api.example.com": PinnedCertificatesTrustEvaluator(
        certificates: Bundle.main.af.certificates,
        acceptSelfSignedCertificates: false,
        performDefaultValidation: true,
        validateHost: true
    )
]

let session = Session(
    serverTrustManager: ServerTrustManager(evaluators: evaluators)
)
```

#### Android (Kotlin)

```kotlin
// Using OkHttp with certificate pinning
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

val certificatePinner = CertificatePinner.Builder()
    .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()

// Network Security Config (res/xml/network_security_config.xml)
/*
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2025-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
*/

// Reference in AndroidManifest.xml
// android:networkSecurityConfig="@xml/network_security_config"
```

### Biometric Authentication

**Use platform biometric APIs securely.**

#### iOS (Swift)

```swift
import LocalAuthentication

class BiometricAuth {
    private let context = LAContext()

    func canUseBiometrics() -> Bool {
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    func authenticate(completion: @escaping (Bool, Error?) -> Void) {
        let reason = "Authenticate to access your account"

        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        ) { success, error in
            DispatchQueue.main.async {
                completion(success, error)
            }
        }
    }

    // SECURE - Combine biometrics with Keychain
    func saveWithBiometricProtection(key: String, data: Data) -> OSStatus {
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,  // Invalidates if biometrics change
            nil
        )

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: access as Any
        ]

        return SecItemAdd(query as CFDictionary, nil)
    }
}
```

#### Android (Kotlin)

```kotlin
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

class BiometricAuth(private val activity: FragmentActivity) {
    private val executor = ContextCompat.getMainExecutor(activity)

    fun authenticate(onSuccess: () -> Unit, onError: (String) -> Unit) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Authenticate to access your account")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val biometricPrompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errString.toString())
                }

                override fun onAuthenticationFailed() {
                    onError("Authentication failed")
                }
            }
        )

        biometricPrompt.authenticate(promptInfo)
    }

    // SECURE - With cryptographic key
    fun authenticateWithCrypto(
        cipher: Cipher,
        onSuccess: (BiometricPrompt.CryptoObject) -> Unit
    ) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setNegativeButtonText("Cancel")
            .build()

        val cryptoObject = BiometricPrompt.CryptoObject(cipher)

        val biometricPrompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    result.cryptoObject?.let { onSuccess(it) }
                }
            }
        )

        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}
```

### Secure Network Communication

**Always use HTTPS. Disable cleartext traffic.**

#### iOS (Swift)

```swift
// Info.plist - App Transport Security (ATS)
// ATS is enabled by default in iOS 9+
/*
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <!-- Only add exceptions if absolutely necessary -->
</dict>
*/

// SECURE - Using URLSession with proper configuration
let configuration = URLSessionConfiguration.default
configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
configuration.urlCache = nil  // Disable caching for sensitive requests

let session = URLSession(configuration: configuration)

// Don't log sensitive data
func makeRequest(token: String) {
    var request = URLRequest(url: url)
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    // Log request without token
    print("Making request to: \(url)")  // Don't log: print("Token: \(token)")
}
```

#### Android (Kotlin)

```kotlin
// Network Security Config - Disable cleartext
/*
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>
</network-security-config>
*/

// AndroidManifest.xml
// android:usesCleartextTraffic="false"

// SECURE - OkHttp configuration
val spec = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
    .tlsVersions(TlsVersion.TLS_1_2, TlsVersion.TLS_1_3)
    .build()

val client = OkHttpClient.Builder()
    .connectionSpecs(listOf(spec))
    .build()
```

### Input Validation & Sanitization

**Validate all user input before use.**

#### iOS (Swift)

```swift
// INSECURE - No validation
func processInput(_ input: String) {
    // Direct use
}

// SECURE - Input validation
struct InputValidator {
    static func validateEmail(_ email: String) -> Bool {
        let pattern = "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
        return email.range(of: pattern, options: .regularExpression) != nil
    }

    static func validateUsername(_ username: String) -> Bool {
        guard username.count >= 3, username.count <= 30 else { return false }
        let pattern = "^[a-zA-Z0-9_]+$"
        return username.range(of: pattern, options: .regularExpression) != nil
    }

    static func sanitizeForDisplay(_ input: String) -> String {
        // Remove potentially dangerous characters for display
        return input
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }
}

// URL validation
func isValidURL(_ string: String) -> Bool {
    guard let url = URL(string: string),
          let scheme = url.scheme else { return false }
    return ["http", "https"].contains(scheme.lowercased())
}
```

#### Android (Kotlin)

```kotlin
object InputValidator {
    private val emailPattern = Patterns.EMAIL_ADDRESS
    private val usernamePattern = Regex("^[a-zA-Z0-9_]{3,30}$")

    fun validateEmail(email: String): Boolean {
        return emailPattern.matcher(email).matches()
    }

    fun validateUsername(username: String): Boolean {
        return usernamePattern.matches(username)
    }

    fun sanitizeForDisplay(input: String): String {
        return input
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
    }

    fun isValidUrl(url: String): Boolean {
        return try {
            val parsed = URL(url)
            parsed.protocol in listOf("http", "https")
        } catch (e: Exception) {
            false
        }
    }
}
```

### Secure WebView

**Configure WebViews securely.**

#### iOS (Swift)

```swift
import WebKit

// INSECURE - Default WebView configuration
let webView = WKWebView()
webView.load(URLRequest(url: url))

// SECURE - Hardened WebView configuration
func createSecureWebView() -> WKWebView {
    let configuration = WKWebViewConfiguration()

    // Disable JavaScript if not needed
    configuration.defaultWebpagePreferences.allowsContentJavaScript = false

    // Disable file access
    configuration.preferences.setValue(false, forKey: "allowFileAccessFromFileURLs")

    let webView = WKWebView(frame: .zero, configuration: configuration)

    // Validate URLs before loading
    webView.navigationDelegate = self

    return webView
}

extension ViewController: WKNavigationDelegate {
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url,
              ["https"].contains(url.scheme?.lowercased()) else {
            decisionHandler(.cancel)
            return
        }

        // Only allow specific domains
        let allowedDomains = ["example.com", "api.example.com"]
        guard let host = url.host,
              allowedDomains.contains(where: { host.hasSuffix($0) }) else {
            decisionHandler(.cancel)
            return
        }

        decisionHandler(.allow)
    }
}
```

#### Android (Kotlin)

```kotlin
// INSECURE - Default WebView
val webView = WebView(context)
webView.settings.javaScriptEnabled = true
webView.loadUrl(url)

// SECURE - Hardened WebView
fun createSecureWebView(context: Context): WebView {
    return WebView(context).apply {
        settings.apply {
            // Disable JavaScript if not needed
            javaScriptEnabled = false

            // Disable file access
            allowFileAccess = false
            allowFileAccessFromFileURLs = false
            allowUniversalAccessFromFileURLs = false

            // Disable content access
            allowContentAccess = false

            // Disable geolocation
            setGeolocationEnabled(false)

            // Disable plugins
            pluginState = WebSettings.PluginState.OFF

            // Disable zoom
            setSupportZoom(false)
        }

        // Validate URLs
        webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val url = request.url
                val allowedDomains = listOf("example.com", "api.example.com")

                if (url.scheme != "https") return true
                if (!allowedDomains.any { url.host?.endsWith(it) == true }) return true

                return false  // Allow navigation
            }
        }
    }
}
```

### Logging Security

**Never log sensitive data.**

```swift
// iOS - INSECURE
print("User token: \(token)")
NSLog("Password: %@", password)

// iOS - SECURE
print("User authenticated successfully")
// Use OSLog for production logging
import os.log
let logger = Logger(subsystem: "com.app.auth", category: "authentication")
logger.info("User \(userId, privacy: .public) logged in")
logger.debug("Token prefix: \(String(token.prefix(4)), privacy: .private)")
```

```kotlin
// Android - INSECURE
Log.d("Auth", "Token: $token")
Log.d("Auth", "Password: $password")

// Android - SECURE
Log.d("Auth", "User authenticated successfully")
// Use Timber with a release tree that strips logs
if (BuildConfig.DEBUG) {
    Timber.plant(Timber.DebugTree())
} else {
    Timber.plant(CrashReportingTree())  // Only logs errors to crash reporting
}
```

### Prevent Screen Capture / Screenshots

```swift
// iOS - Prevent screenshots of sensitive screens
NotificationCenter.default.addObserver(
    self,
    selector: #selector(didTakeScreenshot),
    name: UIApplication.userDidTakeScreenshotNotification,
    object: nil
)

// Prevent screen recording (partial)
if UIScreen.main.isCaptured {
    // Hide sensitive content
}
```

```kotlin
// Android - Prevent screenshots
window.setFlags(
    WindowManager.LayoutParams.FLAG_SECURE,
    WindowManager.LayoutParams.FLAG_SECURE
)
```

## Security Checklist

### Data Storage
- [ ] Sensitive data stored in Keychain (iOS) / EncryptedSharedPreferences (Android)
- [ ] No sensitive data in UserDefaults/SharedPreferences
- [ ] No sensitive data in plain text files
- [ ] Database encrypted if storing sensitive data

### Network
- [ ] Certificate pinning implemented
- [ ] Cleartext traffic disabled
- [ ] TLS 1.2+ enforced
- [ ] API tokens not logged

### Authentication
- [ ] Biometric auth with cryptographic binding
- [ ] Session tokens stored securely
- [ ] Secure logout (clear all sensitive data)
- [ ] Rate limiting on auth attempts

### WebView
- [ ] JavaScript disabled if not needed
- [ ] File access disabled
- [ ] URL validation before loading
- [ ] Domain whitelist enforced

### General
- [ ] Input validation on all user input
- [ ] No sensitive data in logs
- [ ] Screenshot prevention on sensitive screens
- [ ] ProGuard/R8 obfuscation enabled (Android)
- [ ] App Transport Security enabled (iOS)

## Anti-Patterns to Flag

1. **UserDefaults/SharedPreferences for tokens** - Use Keychain/EncryptedSharedPreferences
2. **Disabled certificate validation** - MitM vulnerability
3. **JavaScript enabled in WebView unnecessarily** - XSS risk
4. **Logging tokens/passwords** - Credential exposure
5. **Cleartext traffic allowed** - Data interception
6. **Biometrics without crypto binding** - Bypass possible
7. **Hardcoded API keys** - Credential in binary
8. **Disabled ATS (iOS)** - Allows insecure connections
9. **allowFileAccessFromFileURLs** - Local file access
10. **No input validation** - Injection vulnerabilities
