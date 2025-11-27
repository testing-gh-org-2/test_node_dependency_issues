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

// ⚠️ Hardcoded credentials vulnerability
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
  // ⚠️ SQL Injection vulnerability - CodeQL should detect this
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  res.send(`Query would execute: ${query}`);
});

app.post('/update-config', (req, res) => {
  const config = {};
  // ⚠️ Prototype Pollution vulnerability - CodeQL should detect this
  const key = req.body.key;
  const value = req.body.value;
  config[key] = value;
  res.json({ message: 'Config updated', config });
});

app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  // ⚠️ Reflected XSS vulnerability
  res.send(`<h1>Search Results for: ${searchTerm}</h1>`);
});

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // ⚠️ Command Injection vulnerability
  exec(`ping ${host}`, (error, stdout, stderr) => {
    if (error) {
      res.send(`Error: ${error.message}`);
      return;
    }
    res.send(`<pre>${stdout}</pre>`);
  });
});

app.get('/calc', (req, res) => {
  const expression = req.query.expr;
  // ⚠️ Code Injection vulnerability
  try {
    const result = eval(expression);
    res.send(`Result: ${result}`);
  } catch (error) {
    res.send('Error in expression');
  }
});

app.get('/file', (req, res) => {
  const filename = req.query.name;
  // ⚠️ Path Traversal vulnerability
  const filePath = './uploads/' + filename;
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      res.status(404).send('File not found');
      return;
    }
    res.send(data);
  });
});

app.get('/token', (req, res) => {
  // ⚠️ Insecure random number generation
  const token = Math.random().toString(36).substring(7);
  res.json({ sessionToken: token });
});

app.get('/fetch', (req, res) => {
  const url = req.query.url;
  // ⚠️ SSRF (Server-Side Request Forgery) vulnerability
  https.get(url, (response) => {
    let data = '';
    response.on('data', (chunk) => { data += chunk; });
    response.on('end', () => { res.send(data); });
  }).on('error', (err) => {
    res.send(`Error: ${err.message}`);
  });
});

app.get('/validate', (req, res) => {
  const email = req.query.email;
  // ⚠️ ReDoS (Regular Expression Denial of Service) vulnerability
  const emailRegex = /^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]+$/;
  const isValid = emailRegex.test(email);
  res.json({ valid: isValid });
});

app.post('/login', (req, res) => {
  const username = req.body.username;
  // ⚠️ NoSQL Injection vulnerability
  const query = { username: username };
  res.json({ message: 'Would query MongoDB with:', query });
});

app.post('/ai-prompt', (req, res) => {
  const userInput = req.body.prompt;
  // ⚠️ Prompt Injection vulnerability - AI/LLM security issue
  // Direct user input passed to AI without sanitization
  const systemPrompt = `You are a helpful assistant. User asks: ${userInput}`;
  res.json({ systemPrompt: systemPrompt });
});

app.post('/update-profile', (req, res) => {
  const user = { id: 1, name: 'John', role: 'user', isAdmin: false };
  // ⚠️ Mass Assignment vulnerability - allows unauthorized field modification
  Object.assign(user, req.body);
  res.json({ message: 'Profile updated', user: user });
});

app.get('/verify', (req, res) => {
  const token = req.query.token;
  // ⚠️ Insecure JWT handling - no signature verification
  const parts = token.split('.');
  const payload = Buffer.from(parts[1], 'base64').toString();
  res.json({ decoded: JSON.parse(payload) });
});

app.post('/webhook', (req, res) => {
  // ⚠️ Missing webhook signature verification
  // Accepts data from any source without validation
  const data = req.body;
  console.log('Webhook received:', data);
  res.json({ status: 'processed' });
});

app.get('/redirect', (req, res) => {
  const target = req.query.url;
  // ⚠️ Open Redirect vulnerability
  res.redirect(target);
});

app.get('/api/hello', (req, res) => {
  res.json({
    message: 'Hello from Express API!',
    timestamp: new Date().toISOString(),
    status: 'success'
  });
});

app.post('/api/echo', (req, res) => {
  res.json({
    message: 'Echo endpoint',
    received: req.body,
    timestamp: new Date().toISOString()
  });
});

app.get('/encrypt', (req, res) => {
  const data = req.query.data;
  // ⚠️ Weak cryptographic algorithm - MD5 is insecure
  const hash = crypto.createHash('md5').update(data).digest('hex');
  res.json({ hash: hash });
});

app.post('/upload', (req, res) => {
  const fileName = req.body.fileName;
  const content = req.body.content;
  // ⚠️ Arbitrary File Write vulnerability
  fs.writeFileSync(fileName, content);
  res.json({ message: 'File written', file: fileName });
});

app.get('/exec-code', (req, res) => {
  const code = req.query.code;
  // ⚠️ VM Escape vulnerability - dangerous use of vm module
  const sandbox = {};
  vm.runInNewContext(code, sandbox);
  res.json({ result: 'Code executed', sandbox: sandbox });
});

app.delete('/files', (req, res) => {
  const filePath = req.query.path;
  // ⚠️ Uncontrolled file deletion
  fs.unlinkSync(filePath);
  res.json({ message: 'File deleted', path: filePath });
});

app.get('/read-env', (req, res) => {
  // ⚠️ Information Disclosure - exposing environment variables
  res.json({ env: process.env });
});

app.post('/deserialize', (req, res) => {
  const data = req.body.data;
  // ⚠️ Insecure Deserialization vulnerability
  const obj = JSON.parse(data);
  if (obj.constructor && obj.constructor.name) {
    res.json({ type: obj.constructor.name, data: obj });
  }
  res.json({ obj: obj });
});

app.get('/template', (req, res) => {
  const template = req.query.tmpl;
  // ⚠️ Server-Side Template Injection
  const rendered = eval('`' + template + '`');
  res.send(rendered);
});

app.get('/ldap-query', (req, res) => {
  const username = req.query.user;
  // ⚠️ LDAP Injection vulnerability
  const ldapQuery = `(&(objectClass=user)(uid=${username}))`;
  res.json({ query: ldapQuery });
});

app.post('/xml', (req, res) => {
  const xml = req.body.xml;
  // ⚠️ XML External Entity (XXE) vulnerability
  // Parsing XML without disabling external entities
  res.json({ message: 'XML would be parsed', xml: xml });
});

app.get('/cookie', (req, res) => {
  // ⚠️ Insecure cookie - missing httpOnly and secure flags
  res.cookie('session', '12345', { httpOnly: false, secure: false });
  res.json({ message: 'Cookie set' });
});

app.get('/timing', (req, res) => {
  const password = req.query.password;
  const correctPassword = 'secret123';
  // ⚠️ Timing Attack vulnerability - string comparison leaks timing info
  if (password === correctPassword) {
    res.json({ valid: true });
  } else {
    res.json({ valid: false });
  }
});

app.get('/cors', (req, res) => {
  // ⚠️ Overly permissive CORS policy
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.json({ data: 'sensitive data' });
});

app.post('/process', (req, res) => {
  const input = req.body.input;
  // ⚠️ Billion Laughs Attack - XML bomb vulnerability
  // No input size validation
  res.json({ processed: input });
});

app.get('/zip', (req, res) => {
  const archivePath = req.query.file;
  // ⚠️ Zip Slip vulnerability - path traversal in archives
  const extractPath = '/tmp/' + archivePath;
  res.json({ extracting: extractPath });
});

app.get('/buffer', (req, res) => {
  const size = parseInt(req.query.size);
  // ⚠️ Buffer Overflow - no size validation
  const buffer = Buffer.allocUnsafe(size);
  res.json({ bufferSize: buffer.length });
});

app.post('/spawn-process', (req, res) => {
  const command = req.body.command;
  const args = req.body.args;
  // ⚠️ Command Injection via spawn
  const child = spawn(command, args, { shell: true });
  child.stdout.on('data', (data) => {
    res.write(data);
  });
  child.on('close', () => res.end());
});

app.get('/dns-lookup', (req, res) => {
  const hostname = req.query.host;
  // ⚠️ DNS Rebinding vulnerability - no validation
  dns.lookup(hostname, (err, address) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json({ hostname, address });
    }
  });
});

app.post('/regex-test', (req, res) => {
  const pattern = req.body.pattern;
  const input = req.body.input;
  // ⚠️ ReDoS via user-controlled regex
  const regex = new RegExp(pattern);
  const match = regex.test(input);
  res.json({ match });
});

app.get('/insecure-random', (req, res) => {
  // ⚠️ Cryptographically weak random generation for security token
  const token = Math.random().toString(36) + Date.now().toString(36);
  const sessionId = Math.floor(Math.random() * 1000000);
  res.json({ token, sessionId });
});

app.post('/function-constructor', (req, res) => {
  const code = req.body.code;
  // ⚠️ Code Injection via Function constructor
  const fn = new Function('return ' + code);
  const result = fn();
  res.json({ result });
});

app.get('/hardcoded-credentials', (req, res) => {
  // ⚠️ Multiple hardcoded credentials
  const config = {
    dbPassword: 'password123',
    apiKey: 'sk-1234567890abcdef',
    jwtSecret: 'my-secret-key',
    awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
    awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  };
  res.json(config);
});

app.post('/unsafe-merge', (req, res) => {
  const target = {};
  const source = req.body;
  // ⚠️ Prototype Pollution via unsafe merge
  for (let key in source) {
    target[key] = source[key];
  }
  res.json({ merged: target });
});

app.get('/race-condition', (req, res) => {
  const filename = req.query.file;
  // ⚠️ TOCTOU (Time-of-check Time-of-use) vulnerability
  if (fs.existsSync(filename)) {
    const content = fs.readFileSync(filename, 'utf8');
    res.send(content);
  } else {
    res.status(404).send('File not found');
  }
});

app.post('/unvalidated-redirect', (req, res) => {
  const url = req.body.redirect_url;
  // ⚠️ Unvalidated Redirect vulnerability
  res.writeHead(302, { Location: url });
  res.end();
});

app.get('/sensitive-data-log', (req, res) => {
  const password = req.query.password;
  const creditCard = req.query.cc;
  // ⚠️ Sensitive data in logs
  console.log('User login attempt:', { password, creditCard });
  res.json({ message: 'Logged' });
});

app.get('/missing-rate-limit', (req, res) => {
  // ⚠️ Missing rate limiting on sensitive endpoint
  const username = req.query.username;
  const password = req.query.password;
  const isValid = (username === 'admin' && password === 'admin123');
  res.json({ authenticated: isValid });
});

app.post('/unsafe-deserialization', (req, res) => {
  const serialized = req.body.data;
  // ⚠️ Unsafe deserialization with reviver function
  const obj = JSON.parse(serialized, (key, value) => {
    if (value && value.__proto__) {
      return value;
    }
    return value;
  });
  res.json(obj);
});

app.get('/cleartext-transmission', (req, res) => {
  const apiKey = req.query.apiKey;
  // ⚠️ Sensitive data transmitted in cleartext
  res.send(`Your API key is: ${apiKey}`);
});

app.post('/xxe-vulnerable', (req, res) => {
  const xml = req.body.xml;
  // ⚠️ XXE vulnerability - processing external entities
  const parseString = require('xml2js').parseString;
  parseString(xml, { async: false }, (err, result) => {
    res.json({ parsed: result });
  });
});

app.get('/integer-overflow', (req, res) => {
  const num1 = parseInt(req.query.a);
  const num2 = parseInt(req.query.b);
  // ⚠️ Integer overflow - no bounds checking
  const result = num1 * num2;
  const buffer = Buffer.alloc(result);
  res.json({ size: result, allocated: buffer.length });
});

app.post('/ldap-injection', (req, res) => {
  const username = req.body.username;
  const filter = req.body.filter;
  // ⚠️ LDAP Injection
  const ldapQuery = `(&(objectClass=person)(uid=${username})(${filter}))`;
  res.json({ query: ldapQuery });
});

app.get('/memory-leak', (req, res) => {
  // ⚠️ Potential memory leak - storing unbounded data
  global.cache = global.cache || [];
  global.cache.push(req.query.data);
  res.json({ cacheSize: global.cache.length });
});

app.post('/crypto-weak-key', (req, res) => {
  const data = req.body.data;
  // ⚠️ Weak encryption - DES algorithm
  const cipher = crypto.createCipher('des', 'weak-password');
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  res.json({ encrypted });
});

app.get('/shell-injection', (req, res) => {
  const filename = req.query.file;
  // ⚠️ Shell injection via string interpolation
  exec(`cat ${filename}`, (error, stdout, stderr) => {
    res.send(stdout || stderr || error?.message);
  });
});

// CWE-502: Deserialization of Untrusted Data
app.post('/deserialize', (req, res) => {
  const serializedData = req.body.data;
  // ⚠️ CWE-502: Unsafe deserialization using node-serialize
  try {
    const obj = serialize.unserialize(serializedData);
    res.json({ result: obj });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/deserialize-eval', (req, res) => {
  const payload = req.body.payload;
  // ⚠️ CWE-502: Deserialization with eval
  try {
    const obj = eval('(' + payload + ')');
    res.json({ deserialized: obj });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/deserialize-json', (req, res) => {
  const data = req.body.data;
  // ⚠️ CWE-502: Unsafe JSON deserialization with reviver allowing __proto__
  const parsed = JSON.parse(data, function(key, value) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      return value; // Allows prototype pollution
    }
    return value;
  });
  res.json(parsed);
});

app.post('/pickle-like', (req, res) => {
  const serialized = req.body.serialized;
  // ⚠️ CWE-502: Unsafe object reconstruction
  const obj = {};
  const parts = serialized.split(';');
  parts.forEach(part => {
    if (part.includes('=')) {
      const [key, value] = part.split('=');
      obj[key] = eval(value); // Dangerous eval on untrusted data
    }
  });
  res.json({ reconstructed: obj });
});

// CWE-022: Path Traversal
app.get('/read-file-cwe22', (req, res) => {
  const fileName = req.query.file;
  // ⚠️ CWE-022: Path Traversal - no sanitization
  const fullPath = path.join(__dirname, 'uploads', fileName);
  fs.readFile(fullPath, 'utf8', (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.send(data);
    }
  });
});

app.post('/write-file-cwe22', (req, res) => {
  const fileName = req.body.filename;
  const content = req.body.content;
  // ⚠️ CWE-022: Path Traversal on write operations
  const filePath = './data/' + fileName; // No path normalization
  fs.writeFile(filePath, content, (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json({ success: true, path: filePath });
    }
  });
});

app.get('/download-cwe22', (req, res) => {
  const file = req.query.path;
  // ⚠️ CWE-022: Directory traversal in download
  const downloadPath = '/var/www/files/' + file;
  res.download(downloadPath);
});

app.delete('/delete-file-cwe22', (req, res) => {
  const target = req.query.target;
  // ⚠️ CWE-022: Path traversal allowing deletion of arbitrary files
  fs.unlink('./files/' + target, (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json({ deleted: target });
    }
  });
});

app.get('/list-dir-cwe22', (req, res) => {
  const dir = req.query.directory;
  // ⚠️ CWE-022: Directory listing with path traversal
  fs.readdir('./public/' + dir, (err, files) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      res.json({ files });
    }
  });
});

// CWE-094: Code Injection
app.post('/eval-code-cwe94', (req, res) => {
  const code = req.body.code;
  // ⚠️ CWE-094: Direct code injection via eval
  try {
    const result = eval(code);
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/vm-run-cwe94', (req, res) => {
  const script = req.body.script;
  // ⚠️ CWE-094: Code injection via VM without proper sandboxing
  const context = { require, process, console };
  vm.createContext(context);
  try {
    const result = vm.runInContext(script, context);
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/function-exec-cwe94', (req, res) => {
  const userCode = req.body.code;
  const params = req.body.params || [];
  // ⚠️ CWE-094: Dynamic function creation with user input
  try {
    const fn = new Function(...params, userCode);
    const result = fn();
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/template-inject-cwe94', (req, res) => {
  const template = req.body.template;
  const data = req.body.data;
  // ⚠️ CWE-094: Template injection
  const compiled = eval('`' + template + '`');
  res.send(compiled);
});

app.post('/require-inject-cwe94', (req, res) => {
  const moduleName = req.body.module;
  // ⚠️ CWE-094: Dynamic require with user input
  try {
    const module = require(moduleName);
    res.json({ loaded: moduleName, exports: Object.keys(module) });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// CWE-918: Server-Side Request Forgery (SSRF)
app.get('/proxy-cwe918', (req, res) => {
  const targetUrl = req.query.url;
  // ⚠️ CWE-918: SSRF - fetching arbitrary URLs
  https.get(targetUrl, (response) => {
    let data = '';
    response.on('data', (chunk) => { data += chunk; });
    response.on('end', () => { res.send(data); });
  }).on('error', (err) => {
    res.status(500).json({ error: err.message });
  });
});

app.post('/webhook-cwe918', (req, res) => {
  const webhookUrl = req.body.webhook_url;
  const payload = req.body.payload;
  // ⚠️ CWE-918: SSRF via webhook without URL validation
  const postData = JSON.stringify(payload);
  const urlObj = new URL(webhookUrl);
  const options = {
    hostname: urlObj.hostname,
    port: urlObj.port || 443,
    path: urlObj.pathname,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': postData.length
    }
  };
  const request = https.request(options, (response) => {
    let data = '';
    response.on('data', (chunk) => { data += chunk; });
    response.on('end', () => { res.json({ response: data }); });
  });
  request.on('error', (err) => {
    res.status(500).json({ error: err.message });
  });
  request.write(postData);
  request.end();
});

app.get('/fetch-image-cwe918', (req, res) => {
  const imageUrl = req.query.image;
  // ⚠️ CWE-918: SSRF allowing access to internal resources
  https.get(imageUrl, (response) => {
    res.setHeader('Content-Type', response.headers['content-type']);
    response.pipe(res);
  }).on('error', (err) => {
    res.status(500).json({ error: err.message });
  });
});

app.post('/api-forward-cwe918', (req, res) => {
  const apiEndpoint = req.body.endpoint;
  const method = req.body.method || 'GET';
  // ⚠️ CWE-918: Open proxy forwarding requests
  const urlObj = new URL(apiEndpoint);
  const options = {
    hostname: urlObj.hostname,
    port: urlObj.port,
    path: urlObj.pathname + urlObj.search,
    method: method
  };
  https.request(options, (response) => {
    let data = '';
    response.on('data', (chunk) => { data += chunk; });
    response.on('end', () => { res.json({ data }); });
  }).end();
});

app.get('/metadata-cwe918', (req, res) => {
  const serviceUrl = req.query.service;
  // ⚠️ CWE-918: SSRF to cloud metadata endpoints
  // Could access http://169.254.169.254/latest/meta-data/
  https.get(serviceUrl, (response) => {
    let metadata = '';
    response.on('data', (chunk) => { metadata += chunk; });
    response.on('end', () => { res.json({ metadata }); });
  }).on('error', (err) => {
    res.status(500).json({ error: err.message });
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl
  });
});

// CWE-79: Cross-Site Scripting (XSS)
app.get('/search-xss', (req, res) => {
  const query = req.query.q;
  // ⚠️ CWE-79: Reflected XSS - no output encoding
  res.send(`<h1>Search Results for: ${query}</h1><p>No results found</p>`);
});

app.post('/comment-xss', (req, res) => {
  const comment = req.body.comment;
  // ⚠️ CWE-79: Stored XSS vulnerability
  global.comments = global.comments || [];
  global.comments.push(comment);
  res.send(`<div>Comment added: ${comment}</div>`);
});

// CWE-287: Improper Authentication
app.post('/admin-access', (req, res) => {
  const username = req.body.username;
  const isAdmin = req.body.isAdmin;
  // ⚠️ CWE-287: Authentication bypass - trusting client data
  if (isAdmin === 'true' || isAdmin === true) {
    res.json({ access: 'granted', role: 'admin' });
  } else {
    res.json({ access: 'denied' });
  }
});

app.get('/weak-session', (req, res) => {
  const userId = req.query.user;
  // ⚠️ CWE-287: Weak session management - predictable session IDs
  const sessionId = userId + '_' + Date.now();
  res.json({ sessionId, message: 'Logged in' });
});

// CWE-89: SQL Injection
app.get('/user-sql', (req, res) => {
  const userId = req.query.id;
  // ⚠️ CWE-89: SQL Injection vulnerability
  const query = `SELECT * FROM users WHERE id = '${userId}'`;
  res.json({ query, warning: 'This would execute: ' + query });
});

app.post('/login-sql', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  // ⚠️ CWE-89: SQL Injection in authentication
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  res.json({ query, message: 'SQL query would be executed' });
});

// CWE-352: Cross-Site Request Forgery (CSRF)
app.post('/transfer-money', (req, res) => {
  const amount = req.body.amount;
  const toAccount = req.body.to;
  // ⚠️ CWE-352: No CSRF token validation
  res.json({ 
    message: `Transferred $${amount} to account ${toAccount}`,
    warning: 'No CSRF protection'
  });
});

app.post('/delete-account', (req, res) => {
  const accountId = req.body.accountId;
  // ⚠️ CWE-352: State-changing operation without CSRF protection
  res.json({ message: `Account ${accountId} deleted`, csrf: 'missing' });
});

// CWE-434: Unrestricted Upload of File with Dangerous Type
app.post('/upload-file', (req, res) => {
  const filename = req.body.filename;
  const content = req.body.content;
  // ⚠️ CWE-434: No file type validation
  const uploadPath = './uploads/' + filename;
  fs.writeFileSync(uploadPath, content);
  res.json({ message: 'File uploaded', path: uploadPath });
});

app.post('/avatar-upload', (req, res) => {
  const file = req.body.file;
  const extension = req.body.extension;
  // ⚠️ CWE-434: Accepting dangerous file extensions
  const filename = 'avatar_' + Date.now() + extension;
  res.json({ uploaded: filename, warning: 'No extension validation' });
});

// CWE-611: Improper Restriction of XML External Entity Reference (XXE)
app.post('/parse-xml', (req, res) => {
  const xml = req.body.xml;
  // ⚠️ CWE-611: XXE vulnerability - external entities enabled
  const parseString = require('xml2js').parseString;
  parseString(xml, { 
    async: false,
    // External entities not disabled
  }, (err, result) => {
    if (err) {
      res.status(400).json({ error: err.message });
    } else {
      res.json({ parsed: result });
    }
  });
});

app.post('/soap-request', (req, res) => {
  const soapXml = req.body.soap;
  // ⚠️ CWE-611: Processing untrusted XML with external entities
  res.json({ message: 'SOAP request processed', xml: soapXml });
});

// CWE-798: Use of Hard-coded Credentials
app.get('/db-config', (req, res) => {
  // ⚠️ CWE-798: Hardcoded database credentials
  const dbConfig = {
    host: 'localhost',
    user: 'admin',
    password: 'P@ssw0rd123',
    database: 'production_db',
    apiKey: 'sk-live-1234567890abcdef',
    awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
    privateKey: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...'
  };
  res.json(dbConfig);
});

app.get('/service-auth', (req, res) => {
  // ⚠️ CWE-798: Hardcoded service credentials
  const credentials = {
    smtpPassword: 'email_pass_2024',
    ftpPassword: 'ftp123456',
    adminToken: 'bearer_token_12345'
  };
  res.json(credentials);
});

// CWE-776: Improper Restriction of Recursive Entity References in DTDs (XML Bomb)
app.post('/xml-bomb', (req, res) => {
  const xmlData = req.body.xml;
  // ⚠️ CWE-776: Vulnerable to XML bomb/billion laughs attack
  const parser = require('xml2js');
  parser.parseString(xmlData, (err, result) => {
    if (err) {
      res.status(400).json({ error: err.message });
    } else {
      res.json({ parsed: result });
    }
  });
});

app.post('/expand-entities', (req, res) => {
  const xml = req.body.data;
  // ⚠️ CWE-776: Unlimited entity expansion
  res.json({ message: 'Processing XML with entity expansion', data: xml });
});

// CWE-400: Uncontrolled Resource Consumption
app.post('/process-array', (req, res) => {
  const size = req.body.size;
  // ⚠️ CWE-400: No limit on array size - DoS vulnerability
  const arr = new Array(parseInt(size));
  for (let i = 0; i < size; i++) {
    arr[i] = Math.random();
  }
  res.json({ processed: arr.length });
});

app.get('/recursive-operation', (req, res) => {
  const depth = parseInt(req.query.depth);
  // ⚠️ CWE-400: Uncontrolled recursion
  function recurse(n) {
    if (n <= 0) return 1;
    return n * recurse(n - 1);
  }
  const result = recurse(depth);
  res.json({ result });
});

// CWE-732: Incorrect Permission Assignment for Critical Resource
app.post('/create-file-permissions', (req, res) => {
  const filename = req.body.filename;
  const content = req.body.content;
  // ⚠️ CWE-732: World-writable file permissions
  const filePath = './data/' + filename;
  fs.writeFileSync(filePath, content, { mode: 0o777 });
  res.json({ created: filePath, permissions: '777' });
});

app.get('/sensitive-file', (req, res) => {
  // ⚠️ CWE-732: Exposing sensitive files without access control
  const configPath = './config/secrets.json';
  if (fs.existsSync(configPath)) {
    const secrets = fs.readFileSync(configPath, 'utf8');
    res.send(secrets);
  } else {
    res.json({ message: 'No secrets file found' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Something went wrong!',
    message: err.message
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Server is running on http://localhost:${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
