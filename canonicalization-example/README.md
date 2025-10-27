# Canonicalization Example (Node.js)

This example demonstrates:
1. Server-side canonicalization and validation using `express-validator`.
2. Client-side validation using HTML5 `pattern` and a small JS regex.
3. Unit tests (Jest + Supertest) to verify accepted and rejected inputs.
4. An intentionally vulnerable endpoint (`/read-no-validate`) to observe how disabling validation leads to path traversal.

## Files
- `server.js` - Express server with secure and vulnerable endpoints.
- `public/index.html` - Simple client page with forms and client-side validation.
- `tests/read.test.js` - Unit tests.
- `files/` - directory for sample files (created at runtime or by the /setup-sample endpoint).

## Setup
1. Install Node.js (>=16) and npm.
2. Extract project and run:
   ```bash
   npm install
   npm test        # runs Jest tests
   npm start       # start server on http://localhost:3000
   ```
3. Open `http://localhost:3000` to try the client forms.

## Notes
- The secure `/read` route uses decoding + `path.resolve` and enforces that the resolved path starts with the intended base directory.
- The vulnerable `/read-no-validate` route demonstrates how direct path joins without canonical checks can be abused.
- In a production environment, prefer whitelisting allowed filenames or using safe identifier-to-path mappings rather than accepting arbitrary filenames from clients.
