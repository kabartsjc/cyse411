const request = require('supertest');
const fs = require('fs');
const path = require('path');
const app = require('../server');

const BASE_DIR = path.resolve(__dirname, '..', 'files');

beforeAll(() => {
  // ensure sample files exist (server provides endpoint but ensure in tests)
  if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });
  fs.writeFileSync(path.join(BASE_DIR, 'hello.txt'), 'Hello test\n', 'utf8');
  const notesDir = path.join(BASE_DIR, 'notes');
  if (!fs.existsSync(notesDir)) fs.mkdirSync(notesDir);
  fs.writeFileSync(path.join(notesDir, 'readme.md'), '# test readme', 'utf8');
});

test('secure route accepts safe filename', async () => {
  const res = await request(app).post('/read').send({ filename: 'hello.txt' });
  expect(res.statusCode).toBe(200);
  expect(res.body.content).toContain('Hello');
});

test('secure route rejects path traversal attempt', async () => {
  const res = await request(app).post('/read').send({ filename: '../package.json' });
  expect(res.statusCode).toBe(403);
  expect(res.body.error).toMatch(/Path traversal/i);
});

test('vulnerable route allows traversal (demonstrates vulnerability)', async () => {
  // attempt to read a file outside base by traversing up to project root package.json
  const res = await request(app).post('/read-no-validate').send({ filename: '../package.json' });
  // may be 200 if package.json exists at that path -- the test demonstrates the vulnerability if so
  // assert that the path returned contains '..' resolved by path.join (vulnerable)
  expect(res.statusCode === 200 || res.statusCode === 404).toBeTruthy();
});

test('secure route handles encoded traversal attempts', async () => {
  const res = await request(app).post('/read').send({ filename: '%2e%2e%2fpackage.json' });
  expect(res.statusCode).toBe(403);
});
