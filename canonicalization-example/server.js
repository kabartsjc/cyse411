const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files'); // safe base directory
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// helper to canonicalize and check
function resolveSafe(baseDir, userInput) {
  // decode URI components (to catch %2e %2f etc.)
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {
    // ignore decode errors and use raw input
  }
  const resolved = path.resolve(baseDir, userInput);
  return resolved;
}

// Secure route: validate + canonicalize + enforce base dir
app.post('/read', 
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty()
    .withMessage('filename must not be empty')
    .custom(value => {
      // simple blacklist for suspicious patterns (extra safety)
      if (value.includes('\0')) throw new Error('null byte not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);

    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }

    if (!fs.existsSync(normalized)) {
      return res.status(404).json({ error: 'File not found' });
    }

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  });

// Vulnerable route: intentionally disables validation and canonical checks
app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';
  // directly join (vulnerable)
  const joined = path.join(BASE_DIR, filename);
  // NOTE: this is intentionally vulnerable for demo/testing
  if (!fs.existsSync(joined)) {
    return res.status(404).json({ error: 'File not found', path: joined });
  }
  const content = fs.readFileSync(joined, 'utf8');
  res.json({ path: joined, content });
});

// helper route to create sample files (for demo/testing)
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };
  Object.keys(samples).forEach(k => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });
  res.json({ ok: true, base: BASE_DIR });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});

module.exports = app;
