const express = require('express');
const { exec, spawn } = require('child_process');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const path = require('path');
const vm = require('vm');
const net = require('net');
const dns = require('dns');
const os = require('os');
const serialize = require('node-serialize');

const app = express();
const PORT = process.env.PORT || 3000;

// ⚠️ CWE-798: Hardcoded credentials vulnerability
const DB_PASSWORD = 'admin123';
const API_SECRET = 'secret-key-12345';

// Middleware
// making change 1 to trigger the code QA scan
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
//test 11

// Routes
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Express App</title>
        <style>
          body { 
            font-family: Arial, sans-serif; 
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
            background-color: #f5f5f5;
          }
          .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          }
          h1 { color: #333; }
          .endpoints {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🚀 Express Server is Running!</h1>
          <p>Welcome to your Node.js Express application.</p>
          <div class="endpoints">
            <h3>Available Endpoints:</h3>
            <ul>
              <li><strong>GET /</strong> - This home page</li>
              <li><strong>GET /api/hello</strong> - Simple API endpoint</li>
              <li><strong>POST /api/echo</strong> - Echo back JSON data</li>
            </ul>
          </div>
        </div>
      </body>
    </html>
  `);
});

app.get('/user', (req, res) => {
  const userId = req.query.id;
  // ⚠️ CWE-89: SQL Injection vulnerability - CodeQL should detect this
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  res.send(`Query would execute: ${query}`);
});

app.post('/update-config', (req, res) => {
  const config = {};
  // ⚠️ CWE-1321: Prototype Pollution vulnerability - CodeQL should detect this
  const key = req.body.key;
  const value = req.body.value;
  config[key] = value;
  res.json({ message: 'Config updated', config });
});

app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  // ⚠️ CWE-79: Reflected XSS vulnerability
  res.send(`<h1>Search Results for: ${searchTerm}</h1>`);
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // ⚠️ CWE-78: Command Injection vulnerability
  exec(`ping ${host}`, (error, stdout, stderr) => {
    if (error) {
      res.send(`Error: ${error.message}`);
      return;
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

// CWE-20: Incomplete hostname regexp
app.get('/validate-host', (req, res) => {
  const host = req.query.host;
  // ⚠️ CWE-20: js/incomplete-hostname-regexp - Incomplete regular expression for hostnames
  const hostRegex = /^https?:\/\/[a-z0-9]+\.example\.com/;
  if (hostRegex.test(host)) {
    res.json({ valid: true, message: 'Valid hostname' });
  } else {
    res.json({ valid: false, message: 'Invalid hostname' });
  }
});

// CWE-20: Incomplete URL scheme check
app.get('/check-url', (req, res) => {
  const url = req.query.url;
  // ⚠️ CWE-20: js/incomplete-url-scheme-check - Incomplete URL scheme check
  if (url.startsWith('https://') || url.startsWith('http://')) {
    https.get(url, (response) => {
      res.json({ message: 'URL checked', status: response.statusCode });
    });
  }
});

// CWE-20: Incomplete URL substring sanitization
app.post('/sanitize-url', (req, res) => {
  let url = req.body.url;
  // ⚠️ CWE-20: js/incomplete-url-substring-sanitization
  url = url.replace('javascript:', '');
  res.send(`<a href="${url}">Click here</a>`);
});

// CWE-20: Incorrect suffix check
app.get('/check-file', (req, res) => {
  const filename = req.query.filename;
  // ⚠️ CWE-20: js/incorrect-suffix-check
  if (filename.indexOf('.txt') !== -1) {
    fs.readFile(filename, 'utf8', (err, data) => {
      if (err) {
        res.status(500).send('Error reading file');
      } else {
        res.send(data);
      }
    });
  }
});

// CWE-20: Missing origin check in postMessage
app.get('/postmessage-page', (req, res) => {
  // ⚠️ CWE-20: js/missing-origin-check
  res.send(`
    <script>
      window.addEventListener('message', function(event) {
        // Missing origin verification
        document.getElementById('result').innerHTML = event.data;
      });
    </script>
    <div id="result"></div>
  `);
});

// CWE-20: Missing regexp anchor
app.get('/validate-input', (req, res) => {
  const input = req.query.input;
  // ⚠️ CWE-20: js/regex/missing-regexp-anchor - Missing regular expression anchor
  const pattern = /[0-9]+/;
  if (pattern.test(input)) {
    res.json({ valid: true });
  } else {
    res.json({ valid: false });
  }
});

// CWE-20: Overly permissive regex range
app.get('/check-alpha', (req, res) => {
  const text = req.query.text;
  // ⚠️ CWE-20: js/overly-large-range - Overly permissive regular expression range
  const alphaRegex = /^[A-z]+$/;
  res.json({ isAlpha: alphaRegex.test(text) });
});

// CWE-20: Bad HTML filtering regexp
app.post('/filter-html', (req, res) => {
  let html = req.body.html;
  // ⚠️ CWE-20: js/bad-tag-filter - Bad HTML filtering regexp
  html = html.replace(/<script[^>]*>.*<\/script>/gi, '');
  res.send(html);
});

// CWE-20: Double escaping
app.get('/escape-data', (req, res) => {
  let data = req.query.data;
  // ⚠️ CWE-20: js/double-escaping - Double escaping or unescaping
  data = decodeURIComponent(decodeURIComponent(data));
  res.send(data);
});

// CWE-20: Incomplete HTML attribute sanitization
app.post('/sanitize-attr', (req, res) => {
  let attr = req.body.attr;
  // ⚠️ CWE-20: js/incomplete-html-attribute-sanitization
  attr = attr.replace(/"/g, '');
  res.send(`<div data-value="${attr}">Content</div>`);
});

// CWE-20: Incomplete multi-character sanitization
app.post('/clean-input', (req, res) => {
  let input = req.body.input;
  // ⚠️ CWE-20: js/incomplete-multi-character-sanitization
  input = input.replace('../', '');
  res.json({ cleaned: input });
});

// CWE-20: Incomplete string escaping
app.get('/escape-string', (req, res) => {
  let str = req.query.str;
  // ⚠️ CWE-20: js/incomplete-sanitization - Incomplete string escaping or encoding
  str = str.replace(/'/g, "\\'");
  res.send(`<script>var data = '${str}';</script>`);
});

// CWE-22/CWE-23: Path injection
app.get('/read-file', (req, res) => {
  const filename = req.query.file;
  // ⚠️ CWE-22/CWE-23: js/path-injection - Uncontrolled data used in path expression
  const filePath = path.join(__dirname, 'uploads', filename);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      res.status(500).send('Error');
    } else {
      res.send(data);
    }
  });
});

// CWE-73: Template Object Injection
app.get('/render-template', (req, res) => {
  const data = {};
  const key = req.query.key;
  // ⚠️ CWE-73: js/template-object-injection - Template Object Injection
  const value = data[key];
  res.json({ value });
});

// CWE-74: Disabling Electron webSecurity
app.get('/electron-config', (req, res) => {
  // ⚠️ CWE-74: js/disabling-electron-websecurity
  const electronConfig = {
    webPreferences: {
      webSecurity: false,
      nodeIntegration: true
    }
  };
  res.json(electronConfig);
});

// CWE-74: Enabling Node.js integration for Electron
app.get('/electron-node', (req, res) => {
  // ⚠️ CWE-74: js/enabling-electron-renderer-node-integration
  const config = {
    webPreferences: {
      nodeIntegration: true
    }
  };
  res.json(config);
});

// CWE-77/CWE-78: Indirect command line injection
app.post('/indirect-exec', (req, res) => {
  const command = req.body.command;
  const args = req.body.args;
  // ⚠️ CWE-77/CWE-78: js/indirect-command-line-injection
  spawn(command, args.split(' '));
  res.json({ message: 'Command executed' });
});

// CWE-78: Second order command injection
app.post('/save-command', (req, res) => {
  const cmd = req.body.cmd;
  // ⚠️ CWE-78: js/second-order-command-line-injection
  fs.writeFileSync('command.txt', cmd);
  res.json({ saved: true });
});

app.get('/run-saved', (req, res) => {
  const cmd = fs.readFileSync('command.txt', 'utf8');
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

// CWE-78: Shell command from environment
app.get('/env-exec', (req, res) => {
  // ⚠️ CWE-78: js/shell-command-injection-from-environment
  const cmd = process.env.USER_COMMAND || 'ls';
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

// CWE-78: Unsafe shell command from library input
app.post('/library-exec', (req, res) => {
  const input = req.body.input;
  // ⚠️ CWE-78: js/shell-command-constructed-from-input
  exec(`echo ${input}`, (err, stdout) => {
    res.send(stdout);
  });
});

// CWE-78: Unnecessary use of cat
app.get('/cat-file', (req, res) => {
  const file = req.query.file;
  // ⚠️ CWE-78: js/unnecessary-use-of-cat
  exec(`cat ${file}`, (err, stdout) => {
    res.send(stdout);
  });
});

// CWE-79: XSS through exception
app.get('/error-page', (req, res) => {
  try {
    const data = JSON.parse(req.query.json);
    res.json(data);
  } catch (e) {
    // ⚠️ CWE-79: js/xss-through-exception - Exception text reinterpreted as HTML
    res.send(`<h1>Error: ${e.message}</h1>`);
  }
});

// CWE-79: Reflected XSS
app.get('/reflect', (req, res) => {
  const name = req.query.name;
  // ⚠️ CWE-79: js/reflected-xss - Reflected cross-site scripting
  res.send(`<h1>Hello ${name}</h1>`);
});

// CWE-79: Stored XSS
const comments = [];
app.post('/add-comment', (req, res) => {
  const comment = req.body.comment;
  // ⚠️ CWE-79: js/stored-xss - Stored cross-site scripting
  comments.push(comment);
  res.json({ success: true });
});

app.get('/comments', (req, res) => {
  let html = '<h1>Comments</h1>';
  comments.forEach(c => {
    html += `<p>${c}</p>`;
  });
  res.send(html);
});

// CWE-79: Unsafe HTML constructed from input
app.post('/create-html', (req, res) => {
  const content = req.body.content;
  // ⚠️ CWE-79: js/html-constructed-from-input
  const html = `<div>${content}</div>`;
  res.send(html);
});

// CWE-79: Client-side XSS
app.get('/client-xss', (req, res) => {
  // ⚠️ CWE-79: js/xss - Client-side cross-site scripting
  res.send(`
    <script>
      const params = new URLSearchParams(window.location.search);
      document.write(params.get('msg'));
    </script>
  `);
});

// CWE-79: DOM XSS
app.get('/dom-xss', (req, res) => {
  // ⚠️ CWE-79: js/xss-through-dom - DOM text reinterpreted as HTML
  res.send(`
    <script>
      const hash = window.location.hash.substring(1);
      document.getElementById('content').innerHTML = hash;
    </script>
    <div id="content"></div>
  `);
});

// CWE-79: Bad code sanitization
app.post('/sanitize-code', (req, res) => {
  let code = req.body.code;
  // ⚠️ CWE-79: js/bad-code-sanitization - Improper code sanitization
  code = code.replace(/eval/g, '');
  res.send(`<script>${code}</script>`);
});

// CWE-79: Unsafe code construction
app.post('/build-code', (req, res) => {
  const userFunc = req.body.func;
  // ⚠️ CWE-79: js/unsafe-code-construction
  const code = `function run() { ${userFunc} }`;
  res.json({ code });
});

// CWE-79: Unsafe HTML expansion
app.post('/expand-html', (req, res) => {
  let html = req.body.html;
  // ⚠️ CWE-79: js/unsafe-html-expansion - Unsafe expansion of self-closing HTML tag
  html = html.replace(/<(\w+)\/>/, '<$1></$1>');
  res.send(html);
});

// CWE-89: SQL Injection
app.get('/query-user', (req, res) => {
  const username = req.query.username;
  // ⚠️ CWE-89: js/sql-injection - Database query built from user-controlled sources
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  res.json({ query });
});

// CWE-90: LDAP Injection (simulated)
app.get('/ldap-search', (req, res) => {
  const filter = req.query.filter;
  // ⚠️ CWE-90: js/sql-injection (LDAP query pattern)
  const ldapQuery = `(uid=${filter})`;
  res.json({ ldapQuery });
});

// CWE-91: XPath Injection
app.get('/xpath-query', (req, res) => {
  const user = req.query.user;
  // ⚠️ CWE-91: js/xpath-injection - XPath injection
  const xpath = `//user[@name='${user}']`;
  res.json({ xpath });
});

// CWE-93: CRLF Injection
app.get('/set-header', (req, res) => {
  const value = req.query.value;
  // ⚠️ CWE-93: CRLF injection through header
  res.setHeader('X-Custom', value);
  res.send('Header set');
});

// CWE-94: Code injection with eval
app.post('/eval-code', (req, res) => {
  const code = req.body.code;
  // ⚠️ CWE-94/CWE-95: js/code-injection - Code injection
  const result = eval(code);
  res.json({ result });
});

// CWE-94: Code injection with Function constructor
app.post('/function-inject', (req, res) => {
  const code = req.body.code;
  // ⚠️ CWE-94: js/code-injection
  const fn = new Function('x', code);
  res.json({ created: true });
});

// CWE-94: Code injection with vm
app.post('/vm-run', (req, res) => {
  const code = req.body.code;
  // ⚠️ CWE-94: js/code-injection
  const result = vm.runInThisContext(code);
  res.json({ result });
});

// CWE-94: Unsafe dynamic method access
app.get('/dynamic-method', (req, res) => {
  const method = req.query.method;
  const obj = { safe: () => 'safe', admin: () => 'admin' };
  // ⚠️ CWE-94: js/unsafe-dynamic-method-access
  const result = obj[method]();
  res.json({ result });
});

// CWE-94: Code injection from dynamic import
app.get('/dynamic-import', (req, res) => {
  const module = req.query.module;
  // ⚠️ CWE-94: js/code-injection-dynamic-import
  import(module).then(mod => {
    res.json({ loaded: true });
  }).catch(err => {
    res.status(500).json({ error: err.message });
  });
});

// CWE-94: Environment variable injection
app.post('/set-env', (req, res) => {
  const key = req.body.key;
  const value = req.body.value;
  // ⚠️ CWE-94: js/env-key-and-value-injection
  process.env[key] = value;
  res.json({ set: true });
});

// CWE-94: Environment value injection
app.post('/set-env-value', (req, res) => {
  const value = req.body.value;
  // ⚠️ CWE-94: js/env-value-injection
  process.env.USER_DATA = value;
  res.json({ set: true });
});

// CWE-116: Identity replacement
app.post('/replace-text', (req, res) => {
  let text = req.body.text;
  // ⚠️ CWE-116: js/identity-replacement - Replacement of a substring with itself
  text = text.replace('bad', 'bad');
  res.json({ text });
});

// CWE-117: Log injection
app.get('/log-user', (req, res) => {
  const username = req.query.username;
  // ⚠️ CWE-117: js/log-injection - Log injection
  console.log(`User logged in: ${username}`);
  res.json({ logged: true });
});

// CWE-134: Format string injection
app.get('/format-string', (req, res) => {
  const format = req.query.format;
  const value = req.query.value;
  // ⚠️ CWE-134: js/tainted-format-string
  const result = format.replace('%s', value);
  res.send(result);
});

// CWE-178: Case-sensitive middleware path
app.get('/Admin/panel', (req, res) => {
  // ⚠️ CWE-178: js/case-sensitive-middleware-path
  res.send('Admin panel');
});

app.get('/admin/panel', (req, res) => {
  res.send('Should be the same');
});

// CWE-183: Insecure URL whitelist (Angular-style)
app.get('/angular-url', (req, res) => {
  const url = req.query.url;
  // ⚠️ CWE-183: js/angular/insecure-url-whitelist
  const whitelist = ['http://example.com', 'http://safe.com'];
  const regex = /^https?:\/\/example\.com/;
  if (regex.test(url)) {
    res.json({ safe: true });
  }
});

// CWE-183: CORS misconfiguration for credentials
app.get('/cors-creds', (req, res) => {
  const origin = req.headers.origin;
  // ⚠️ CWE-183: js/cors-misconfiguration-for-credentials
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.json({ data: 'sensitive' });
});

// CWE-183: Permissive CORS configuration
app.get('/cors-permissive', (req, res) => {
  // ⚠️ CWE-183: js/cors-permissive-configuration
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', '*');
  res.json({ data: 'public' });
});

// CWE-193: Index out of bounds
app.get('/array-access', (req, res) => {
  const arr = [1, 2, 3];
  const index = parseInt(req.query.index);
  // ⚠️ CWE-193: js/index-out-of-bounds - Off-by-one comparison against length
  if (index < arr.length + 1) {
    res.json({ value: arr[index] });
  }
});

// CWE-197: Shift out of range
app.get('/bit-shift', (req, res) => {
  const value = parseInt(req.query.value);
  const shift = parseInt(req.query.shift);
  // ⚠️ CWE-197: js/shift-out-of-range
  const result = value << shift;
  res.json({ result });
});

// CWE-200: Unsafe external link
app.get('/external-link', (req, res) => {
  const url = req.query.url;
  // ⚠️ CWE-200: js/unsafe-external-link
  res.send(`<a href="${url}" target="_blank">External Link</a>`);
});

// CWE-200: File data in outbound request
app.get('/send-file-data', (req, res) => {
  const file = req.query.file;
  // ⚠️ CWE-200: js/file-access-to-http
  fs.readFile(file, 'utf8', (err, data) => {
    if (!err) {
      https.get(`https://example.com/api?data=${data}`);
    }
  });
  res.json({ sent: true });
});

// CWE-200: Exposure of private files
app.use('/private', express.static('private'));
// ⚠️ CWE-200: js/exposure-of-private-files

// CWE-200: Cross-window information leak
app.get('/cross-window', (req, res) => {
  // ⚠️ CWE-200: js/cross-window-information-leak
  res.send(`
    <script>
      window.opener.postMessage('sensitive-data', '*');
    </script>
  `);
});

// CWE-200: Stack trace exposure
app.get('/error-stack', (req, res) => {
  try {
    throw new Error('Something went wrong');
  } catch (e) {
    // ⚠️ CWE-200: js/stack-trace-exposure
    res.json({ error: e.stack });
  }
});

// CWE-200: Build artifact leak
app.get('/source-map', (req, res) => {
  // ⚠️ CWE-200: js/build-artifact-leak
  res.sendFile(path.join(__dirname, 'dist', 'app.js.map'));
});

// CWE-200: Clear-text logging
app.post('/login', (req, res) => {
  const password = req.body.password;
  // ⚠️ CWE-200/CWE-312: js/clear-text-logging
  console.log(`Login attempt with password: ${password}`);
  res.json({ success: true });
});

// CWE-200: Clear-text storage
app.post('/store-secret', (req, res) => {
  const secret = req.body.secret;
  // ⚠️ CWE-200/CWE-312: js/clear-text-storage-of-sensitive-data
  fs.writeFileSync('secrets.txt', secret);
  res.json({ stored: true });
});

// CWE-200: Sensitive GET query
app.get('/api/auth', (req, res) => {
  // ⚠️ CWE-200: js/sensitive-get-query
  const apiKey = req.query.apiKey;
  res.json({ authenticated: true });
});

// CWE-312: Password in configuration
const config = {
  // ⚠️ CWE-312: js/password-in-configuration-file
  database: {
    host: 'localhost',
    user: 'admin',
    password: 'SuperSecret123!'
  }
};

// CWE-326: Insufficient key size
app.post('/encrypt-weak', (req, res) => {
  const data = req.body.data;
  // ⚠️ CWE-326: js/insufficient-key-size
  const algorithm = 'des';
  const key = crypto.randomBytes(8);
  const cipher = crypto.createCipheriv(algorithm, key, Buffer.alloc(8));
  const encrypted = cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
  res.json({ encrypted });
});

// CWE-327: Weak cryptographic algorithm
app.post('/hash-md5', (req, res) => {
  const data = req.body.data;
  // ⚠️ CWE-327/CWE-328: js/weak-cryptographic-algorithm
  const hash = crypto.createHash('md5').update(data).digest('hex');
  res.json({ hash });
});

// CWE-327: Biased cryptographic random
app.get('/random-biased', (req, res) => {
  // ⚠️ CWE-327: js/biased-cryptographic-random
  const random = crypto.randomBytes(16).readUInt32BE(0) % 100;
  res.json({ random });
});

// CWE-327: Insufficient password hash
app.post('/hash-password', (req, res) => {
  const password = req.body.password;
  // ⚠️ CWE-327: js/insufficient-password-hash
  const hash = crypto.createHash('sha256').update(password).digest('hex');
  res.json({ hash });
});

// CWE-330/CWE-338: Insecure randomness
app.get('/generate-token', (req, res) => {
  // ⚠️ CWE-330/CWE-338: js/insecure-randomness
  const token = Math.random().toString(36).substring(7);
  res.json({ token });
});

// CWE-330: Hardcoded credentials
const JWT_SECRET = 'hardcoded-secret-key-12345';
// ⚠️ CWE-330: js/hardcoded-credentials

// CWE-340: Predictable token
app.get('/session-token', (req, res) => {
  // ⚠️ CWE-340: js/predictable-token
  const timestamp = Date.now();
  const token = crypto.createHash('md5').update(timestamp.toString()).digest('hex');
  res.json({ token });
});

// CWE-345: JWT missing verification
app.post('/verify-jwt', (req, res) => {
  const token = req.body.token;
  // ⚠️ CWE-345/CWE-347: js/jwt-missing-verification
  const decoded = Buffer.from(token.split('.')[1], 'base64').toString();
  res.json({ user: JSON.parse(decoded) });
});

// CWE-345: Decode JWT without verification
app.get('/decode-jwt', (req, res) => {
  const token = req.query.token;
  // ⚠️ CWE-345/CWE-347: js/decode-jwt-without-verification
  const parts = token.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
  res.json(payload);
});

// CWE-352: Missing CSRF middleware
app.post('/update-profile', (req, res) => {
  // ⚠️ CWE-352: js/missing-token-validation - Missing CSRF protection
  const email = req.body.email;
  res.json({ updated: true, email });
});

// CWE-359: Clear-text cookie
app.post('/set-cookie', (req, res) => {
  const sessionId = req.body.sessionId;
  // ⚠️ CWE-359: js/clear-text-cookie
  res.cookie('sessionId', sessionId, { httpOnly: false, secure: false });
  res.json({ set: true });
});

// CWE-367: File system race condition
app.post('/check-and-write', (req, res) => {
  const filename = req.body.filename;
  const content = req.body.content;
  // ⚠️ CWE-367: js/file-system-race
  if (!fs.existsSync(filename)) {
    fs.writeFileSync(filename, content);
  }
  res.json({ written: true });
});

// CWE-377/378: Insecure temporary file
app.post('/create-temp', (req, res) => {
  const data = req.body.data;
  // ⚠️ CWE-377/378: js/insecure-temporary-file
  const tmpFile = `/tmp/temp-${Date.now()}.txt`;
  fs.writeFileSync(tmpFile, data);
  res.json({ file: tmpFile });
});

// CWE-400: Polynomial ReDoS
app.get('/validate-email', (req, res) => {
  const email = req.query.email;
  // ⚠️ CWE-400/CWE-1333: js/polynomial-redos
  const regex = /^([a-zA-Z0-9]+)+@example\.com$/;
  const isValid = regex.test(email);
  res.json({ isValid });
});

// CWE-400: Inefficient regular expression
app.get('/match-pattern', (req, res) => {
  const input = req.query.input;
  // ⚠️ CWE-400/CWE-1333: js/redos
  const regex = /(a+)+b/;
  const matches = regex.test(input);
  res.json({ matches });
});

// CWE-400: Resource exhaustion from deep traversal
app.post('/deep-traverse', (req, res) => {
  const obj = req.body.obj;
  // ⚠️ CWE-400: js/resource-exhaustion-from-deep-object-traversal
  function traverse(o, depth = 0) {
    if (depth > 1000) return;
    for (let key in o) {
      if (typeof o[key] === 'object') traverse(o[key], depth + 1);
    }
  }
  traverse(obj);
  res.json({ traversed: true });
});

// CWE-400: Remote property injection
app.post('/set-property', (req, res) => {
  const target = {};
  const prop = req.body.prop;
  const value = req.body.value;
  // ⚠️ CWE-400: js/remote-property-injection
  target[prop] = value;
  res.json({ set: true });
});

// CWE-400: Regex injection
app.get('/regex-search', (req, res) => {
  const pattern = req.query.pattern;
  const text = 'Sample text to search';
  // ⚠️ CWE-400: js/regex-injection
  const regex = new RegExp(pattern);
  const found = regex.test(text);
  res.json({ found });
});

// CWE-400: Missing rate limiting
app.post('/api/expensive', (req, res) => {
  // ⚠️ CWE-400/CWE-307: js/missing-rate-limiting
  const result = crypto.pbkdf2Sync(req.body.data, 'salt', 100000, 64, 'sha512');
  res.json({ result: result.toString('hex') });
});

// CWE-400: Resource exhaustion
app.post('/allocate-memory', (req, res) => {
  const size = parseInt(req.body.size);
  // ⚠️ CWE-400: js/resource-exhaustion
  const buffer = Buffer.alloc(size);
  res.json({ allocated: size });
});

// CWE-400: XML bomb
app.post('/parse-xml', (req, res) => {
  const xml = req.body.xml;
  // ⚠️ CWE-400: js/xml-bomb - XML internal entity expansion
  res.json({ parsed: true });
});

// CWE-434: HTTP to file access
app.post('/download-and-save', (req, res) => {
  const url = req.body.url;
  const filename = req.body.filename;
  // ⚠️ CWE-434: js/http-to-file-access
  https.get(url, (response) => {
    const file = fs.createWriteStream(filename);
    response.pipe(file);
    res.json({ downloaded: true });
  });
});

// CWE-441: Client-side request forgery
app.get('/fetch-url', (req, res) => {
  // ⚠️ CWE-441: js/client-side-request-forgery
  res.send(`
    <script>
      const url = new URLSearchParams(window.location.search).get('url');
      fetch(url).then(r => r.text()).then(data => console.log(data));
    </script>
  `);
});

// CWE-441: Server-side request forgery
app.get('/ssrf', (req, res) => {
  const url = req.query.url;
  // ⚠️ CWE-441: js/request-forgery - Server-side request forgery
  https.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.send(data));
  });
});

// CWE-451: Missing X-Frame-Options
app.get('/frameable', (req, res) => {
  // ⚠️ CWE-451: js/missing-x-frame-options
  res.send('<h1>This page can be framed</h1>');
});

// CWE-502: Unsafe deserialization
app.post('/deserialize', (req, res) => {
  const data = req.body.data;
  // ⚠️ CWE-502: js/unsafe-deserialization
  const obj = serialize.unserialize(data);
  res.json({ obj });
});

// CWE-610: Client-side URL redirect
app.get('/client-redirect', (req, res) => {
  const target = req.query.target;
  // ⚠️ CWE-610: js/client-side-unvalidated-url-redirection
  res.send(`
    <script>
      window.location.href = '${target}';
    </script>
  `);
});

// CWE-610: Server-side URL redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  // ⚠️ CWE-610: js/server-side-unvalidated-url-redirection
  res.redirect(url);
});

// CWE-610: XXE - XML external entity
app.post('/parse-xml-xxe', (req, res) => {
  const xml = req.body.xml;
  // ⚠️ CWE-610: js/xxe - XML external entity expansion
  // Simulated XXE vulnerability
  res.json({ parsed: true });
});

// CWE-614: Insecure cookie
app.get('/insecure-cookie', (req, res) => {
  // ⚠️ CWE-614: Cookie without secure flag
  res.cookie('auth', 'token123', { secure: false });
  res.json({ set: true });
});

// CWE-640: Host header poisoning
app.post('/send-email', (req, res) => {
  const host = req.headers.host;
  const email = req.body.email;
  // ⚠️ CWE-640: js/host-header-forgery-in-email-generation
  const resetLink = `http://${host}/reset-password?token=abc`;
  console.log(`Sending email to ${email} with link: ${resetLink}`);
  res.json({ sent: true });
});

// CWE-643: XPath Injection (duplicate for emphasis)
app.get('/xpath-lookup', (req, res) => {
  const username = req.query.username;
  // ⚠️ CWE-643: XPath injection
  const query = `/users/user[username='${username}']`;
  res.json({ query });
});

// CWE-664: User-controlled bypass
app.get('/admin-check', (req, res) => {
  const isAdmin = req.query.isAdmin;
  // ⚠️ CWE-664: js/user-controlled-bypass
  if (isAdmin === 'true') {
    res.json({ message: 'Admin access granted' });
  } else {
    res.status(403).json({ message: 'Access denied' });
  }
});

// CWE-664: Comparison of different kinds
app.post('/authenticate', (req, res) => {
  const userRole = req.body.role;
  // ⚠️ CWE-664: js/different-kinds-comparison-bypass
  if (userRole == 'admin') {
    res.json({ authenticated: true });
  }
});

// CWE-664: Insecure download
app.get('/download-script', (req, res) => {
  // ⚠️ CWE-664: js/insecure-download
  const scriptUrl = 'http://cdn.example.com/script.js';
  res.send(`<script src="${scriptUrl}"></script>`);
});

// CWE-664: Functionality from untrusted domain
app.get('/load-external', (req, res) => {
  const domain = req.query.domain;
  // ⚠️ CWE-664: js/functionality-from-untrusted-domain
  res.send(`<script src="http://${domain}/script.js"></script>`);
});

// CWE-664: Functionality from untrusted source
app.get('/load-script', (req, res) => {
  const src = req.query.src;
  // ⚠️ CWE-664: js/functionality-from-untrusted-source
  res.send(`<script src="${src}"></script>`);
});

// CWE-664: Type confusion through parameter tampering
app.post('/process-data', (req, res) => {
  const data = req.body.data;
  // ⚠️ CWE-664: js/type-confusion-through-parameter-tampering
  if (typeof data === 'string') {
    res.json({ length: data.length });
  } else if (typeof data === 'number') {
    res.json({ value: data });
  }
});

// CWE-664: Empty password in configuration
const dbConfig = {
  // ⚠️ CWE-664: js/empty-password-in-configuration-file
  host: 'localhost',
  user: 'admin',
  password: ''
};

// CWE-668: User-controlled decompression
app.post('/decompress', (req, res) => {
  const data = req.body.data;
  // ⚠️ CWE-668: js/user-controlled-data-decompression
  const zlib = require('zlib');
  zlib.gunzip(Buffer.from(data, 'base64'), (err, result) => {
    if (err) {
      res.status(500).send('Decompression failed');
    } else {
      res.send(result);
    }
  });
});

// CWE-703: Server crash
app.get('/crash', (req, res) => {
  const data = req.query.data;
  // ⚠️ CWE-703: js/server-crash
  JSON.parse(data);
  res.json({ parsed: true });
});

// CWE-703: Unvalidated dynamic method call
app.get('/call-method', (req, res) => {
  const method = req.query.method;
  const obj = {
    safe: () => 'safe',
    dangerous: () => { throw new Error('Dangerous'); }
  };
  // ⚠️ CWE-703: js/unvalidated-dynamic-method-call
  const result = obj[method]();
  res.json({ result });
});

// CWE-704: Implicit operand conversion
app.get('/implicit-convert', (req, res) => {
  const value = req.query.value;
  // ⚠️ CWE-704: js/implicit-operand-conversion
  const result = value * 2;
  res.json({ result });
});

// CWE-704: Invalid prototype value
app.post('/set-proto', (req, res) => {
  const obj = {};
  const proto = req.body.proto;
  // ⚠️ CWE-704: js/invalid-prototype-value
  Object.setPrototypeOf(obj, proto);
  res.json({ set: true });
});

// CWE-704: Assignment to property of primitive
app.get('/primitive-assign', (req, res) => {
  let num = 42;
  // ⚠️ CWE-704: js/property-assignment-on-primitive
  num.customProp = 'value';
  res.json({ num });
});

// CWE-770: Missing rate limiting (another example)
app.post('/brute-force', (req, res) => {
  const password = req.body.password;
  // ⚠️ CWE-770: No rate limiting on password attempts
  if (password === 'secret123') {
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

// CWE-843: Type confusion
app.post('/type-confuse', (req, res) => {
  const value = req.body.value;
  // ⚠️ CWE-843: Type confusion through parameter tampering
  if (Array.isArray(value)) {
    res.json({ type: 'array', length: value.length });
  } else {
    res.json({ type: 'other' });
  }
});

// CWE-916: Weak password hashing
app.post('/register', (req, res) => {
  const password = req.body.password;
  // ⚠️ CWE-916: Insufficient password hashing
  const hash = crypto.createHash('sha1').update(password).digest('hex');
  res.json({ hash });
});

// CWE-1004: Cookie without HttpOnly
app.get('/set-session', (req, res) => {
  // ⚠️ CWE-1004: js/client-exposed-cookie
  res.cookie('session', 'abc123', { httpOnly: false });
  res.json({ set: true });
});

// CWE-1022: Unsafe external link
app.get('/open-link', (req, res) => {
  const url = req.query.url;
  // ⚠️ CWE-1022: js/unsafe-external-link
  res.send(`<a href="${url}" target="_blank" rel="noopener">Link</a>`);
});

// CWE-1275: SameSite None cookie
app.get('/samesite-cookie', (req, res) => {
  // ⚠️ CWE-1275: js/samesite-none-cookie
  res.cookie('tracking', 'value', { sameSite: 'None', secure: false });
  res.json({ set: true });
});

// CWE-77/78: Prototype-polluting assignment
app.post('/merge-config', (req, res) => {
  const userConfig = req.body.config;
  const defaultConfig = { theme: 'light' };
  // ⚠️ CWE-77/78: js/prototype-polluting-assignment
  for (let key in userConfig) {
    defaultConfig[key] = userConfig[key];
  }
  res.json(defaultConfig);
});

// CWE-77: Prototype-polluting function
app.post('/deep-merge', (req, res) => {
  const source = req.body.source;
  const target = {};
  // ⚠️ CWE-77: js/prototype-pollution-utility
  function merge(target, source) {
    for (let key in source) {
      if (typeof source[key] === 'object') {
        target[key] = target[key] || {};
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  merge(target, source);
  res.json(target);
});

// CWE-77: Prototype-polluting merge
app.post('/extend-object', (req, res) => {
  const obj = {};
  const extension = req.body.extension;
  // ⚠️ CWE-77: js/prototype-pollution
  Object.assign(obj, extension);
  res.json(obj);
});

// CWE-248: Server crash from exception
app.get('/throw-error', (req, res) => {
  const type = req.query.type;
  // ⚠️ CWE-248: js/server-crash
  if (type === 'crash') {
    throw new Error('Intentional crash');
  }
  res.json({ ok: true });
});

// CWE-284: Disabling certificate validation
const httpsAgent = new https.Agent({
  // ⚠️ CWE-284: js/disabling-certificate-validation
  rejectUnauthorized: false
});

app.get('/fetch-insecure', (req, res) => {
  const url = req.query.url;
  https.get(url, { agent: httpsAgent }, (response) => {
    res.json({ fetched: true });
  });
});

// CWE-284: Insecure dependency
// ⚠️ CWE-284: js/insecure-dependency
// Using HTTP instead of HTTPS for dependency download in package.json

// CWE-284: Session fixation
app.post('/login-session', (req, res) => {
  const sessionId = req.body.sessionId;
  // ⚠️ CWE-284: js/session-fixation - Failure to abandon session
  res.cookie('sessionId', sessionId);
  res.json({ loggedIn: true });
});

// CWE-295: Certificate validation disabled (TLS)
app.get('/tls-connect', (req, res) => {
  const options = {
    // ⚠️ CWE-295: Disabled certificate validation
    rejectUnauthorized: false
  };
  res.json({ config: options });
});

// CWE-369: Divide by zero
app.get('/divide', (req, res) => {
  const a = parseInt(req.query.a);
  const b = parseInt(req.query.b);
  // ⚠️ CWE-369: Potential divide by zero
  const result = a / b;
  res.json({ result });
});

// CWE-398: TODO/FIXME comments
// ⚠️ CWE-398: js/todo-comment
// TODO: Fix security vulnerability here
// FIXME: This needs proper input validation

// CWE-398: Eval-like call
app.get('/eval-like', (req, res) => {
  const code = req.query.code;
  // ⚠️ CWE-398: js/eval-like-call
  setTimeout(code, 1000);
  res.json({ scheduled: true });
});

// CWE-398: Comparison with NaN
app.get('/check-nan', (req, res) => {
  const value = parseFloat(req.query.value);
  // ⚠️ CWE-398: js/comparison-with-nan
  if (value === NaN) {
    res.json({ isNaN: true });
  } else {
    res.json({ isNaN: false });
  }
});

// CWE-398: Duplicate condition
app.get('/check-value', (req, res) => {
  const val = req.query.val;
  // ⚠️ CWE-398: js/duplicate-condition
  if (val === '1') {
    res.json({ result: 'one' });
  } else if (val === '1') {
    res.json({ result: 'also one' });
  }
});

// CWE-398: Useless expression
app.get('/useless', (req, res) => {
  const x = req.query.x;
  // ⚠️ CWE-398: js/useless-expression
  x + 1;
  res.json({ x });
});

// CWE-398: Identical operands
app.get('/redundant', (req, res) => {
  const a = parseInt(req.query.a);
  // ⚠️ CWE-398: js/redundant-operation
  const result = a - a;
  res.json({ result });
});

// CWE-398: Self assignment
app.get('/self-assign', (req, res) => {
  let value = req.query.value;
  // ⚠️ CWE-398: js/redundant-assignment
  value = value;
  res.json({ value });
});

// CWE-398: Unreachable statement
app.get('/unreachable', (req, res) => {
  res.json({ message: 'Done' });
  return;
  // ⚠️ CWE-398: js/unreachable-statement
  console.log('This will never execute');
});

// CWE-691: Loop bound injection
app.get('/loop-data', (req, res) => {
  const count = parseInt(req.query.count);
  const results = [];
  // ⚠️ CWE-691: js/loop-bound-injection
  for (let i = 0; i < count; i++) {
    results.push(i);
  }
  res.json({ results });
});

// CWE-693: Insecure Helmet configuration
app.get('/helmet-config', (req, res) => {
  // ⚠️ CWE-693: js/insecure-helmet-configuration
  const helmetConfig = {
    contentSecurityPolicy: false,
    frameguard: false
  };
  res.json(helmetConfig);
});

// CWE-710: Hardcoded data interpreted as code
app.get('/hardcoded-eval', (req, res) => {
  // ⚠️ CWE-710: js/hardcoded-data-interpreted-as-code
  const hardcodedCode = 'console.log("Hello")';
  eval(hardcodedCode);
  res.json({ executed: true });
});

// CWE-116: Angular disabling SCE
app.get('/angular-sce', (req, res) => {
  // ⚠️ CWE-116: js/angular/disabling-sce
  res.send(`
    <script>
      angular.module('app', []).config(function($sceProvider) {
        $sceProvider.enabled(false);
      });
    </script>
  `);
});

// CWE-74: Enabling Electron insecure content
app.get('/electron-insecure', (req, res) => {
  // ⚠️ CWE-74: js/enabling-electron-insecure-content
  const config = {
    webPreferences: {
      allowRunningInsecureContent: true
    }
  };
  res.json(config);
});

// CWE-435/436: Insecure HTTP parser
app.get('/http-parser', (req, res) => {
  // ⚠️ CWE-435/436: js/insecure-http-parser
  const http = require('http');
  http.createServer({ insecureHTTPParser: true }, (req, res) => {
    res.end('OK');
  });
  res.json({ created: true });
});

// CWE-561: Trivial conditional
app.get('/trivial', (req, res) => {
  const value = true;
  // ⚠️ CWE-561: js/trivial-conditional
  if (value) {
    res.json({ always: 'true' });
  }
});

// CWE-563: Useless assignment to local
app.get('/useless-local', (req, res) => {
  let temp = req.query.value;
  // ⚠️ CWE-563: js/useless-assignment-to-local
  temp = 'overwritten';
  temp = 'again';
  res.json({ value: temp });
});

// CWE-570: Comparison of identical expressions
app.get('/identical-compare', (req, res) => {
  const x = parseInt(req.query.x);
  // ⚠️ CWE-570/571: js/comparison-of-identical-expressions
  if (x === x) {
    res.json({ always: 'equal' });
  }
});

// CWE-610: Zipslip vulnerability
app.post('/extract-zip', (req, res) => {
  const zipPath = req.body.zipPath;
  const targetDir = req.body.targetDir;
  // ⚠️ CWE-610: js/zipslip - Arbitrary file access during archive extraction
  res.json({ message: 'Extraction simulated - vulnerable to zipslip' });
});

// CWE-670: Whitespace contradicts precedence
app.get('/precedence', (req, res) => {
  const a = 2, b = 3, c = 4;
  // ⚠️ CWE-670: js/whitespace-contradicts-precedence
  const result = a + b * c;
  res.json({ result });
});

// CWE-670: Misleading indentation
app.get('/misleading', (req, res) => {
  const condition = req.query.condition === 'true';
  // ⚠️ CWE-670: js/misleading-indentation-after-control-statement
  if (condition)
    console.log('Condition is true');
    res.json({ message: 'Response sent' });
});

// CWE-670: Deleting non-property
app.get('/delete-var', (req, res) => {
  let myVar = 'value';
  // ⚠️ CWE-670: js/deletion-of-non-property
  delete myVar;
  res.json({ deleted: true });
});

// CWE-676: Use of eval
app.post('/execute-eval', (req, res) => {
  const expression = req.body.expression;
  // ⚠️ CWE-676: js/eval-call - Use of eval
  const result = eval(expression);
  res.json({ result });
});

// CWE-691: Exit from finally
app.get('/finally-exit', (req, res) => {
  try {
    throw new Error('Test');
  } catch (e) {
    console.log(e.message);
  } finally {
    // ⚠️ CWE-691: js/exit-from-finally
    return res.json({ exited: 'from finally' });
  }
});

// CWE-691: Inconsistent loop direction
app.get('/loop-direction', (req, res) => {
  const results = [];
  // ⚠️ CWE-691: js/inconsistent-loop-direction
  for (let i = 10; i < 0; i--) {
    results.push(i);
  }
  res.json({ results });
});

// Hardcoded secrets (GitHub token, AWS keys)
// ⚠️ CWE-798: Hardcoded secrets
const GITHUB_TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----';

// Server start
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
