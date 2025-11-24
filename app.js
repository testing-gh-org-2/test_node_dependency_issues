const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const path = require('path');
const vm = require('vm');

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

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl
  });
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
