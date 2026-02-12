// CodeQL: Command Injection vulnerability (js/command-line-injection)
const { exec, execSync, spawn } = require('child_process');

// Vulnerable: User input directly in exec()
function runCommand(req, res) {
  const userInput = req.query.cmd;
  exec('ls -la ' + userInput, (error, stdout, stderr) => {
    res.send(stdout);
  });
}

// Vulnerable: Template literal command injection
function pingHost(req, res) {
  const host = req.body.host;
  exec(`ping -c 4 ${host}`, (error, stdout) => {
    res.send(stdout);
  });
}

// Vulnerable: execSync with user input
function getFileInfo(req, res) {
  const filename = req.params.filename;
  const result = execSync('file ' + filename);
  res.send(result.toString());
}

// Vulnerable: spawn with shell option and user input
function searchFiles(req, res) {
  const pattern = req.query.pattern;
  const child = spawn('grep', ['-r', pattern, '/var/log'], { shell: true });
  child.stdout.on('data', (data) => res.write(data));
  child.on('close', () => res.end());
}

module.exports = { runCommand, pingHost, getFileInfo, searchFiles };