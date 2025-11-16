const fs = require("fs");
const path = require("path");

function readFile(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function fileContains(content, substring) {
  return content.includes(substring);
}

function fileNotContains(content, substring) {
  return !content.includes(substring);
}

function grade() {
  const serverPath = path.join(__dirname, "..", "src", "server.js");
  const loginPath = path.join(__dirname, "..", "public", "login.html");

  const serverContent = readFile(serverPath);
  const loginContent = readFile(loginPath);

  let total = 0;
  let max = 10; // number of positive checks

  console.log("== FastBank Auth Lab Autograder ==\n");

  // 1) No fast hash (sha256 via crypto)
  if (fileNotContains(serverContent, "crypto.createHash")) {
    console.log("[+] PASS: crypto.createHash (fast hash) removed.");
    total++;
  } else {
    console.log("[-] FAIL: crypto.createHash still present (fast hash).");
  }

  if (fileNotContains(serverContent, "sha256")) {
    console.log("[+] PASS: 'sha256' no longer referenced in server.js.");
    total++;
  } else {
    console.log("[-] FAIL: 'sha256' still appears in server.js.");
  }

  // 2) bcrypt usage
  if (fileContains(serverContent, "bcrypt.hash")) {
    console.log("[+] PASS: bcrypt.hash used (password hashing).");
    total++;
  } else {
    console.log("[-] FAIL: bcrypt.hash not found (password hashing).");
  }

  if (fileContains(serverContent, "bcrypt.compare")) {
    console.log("[+] PASS: bcrypt.compare used (password verification).");
    total++;
  } else {
    console.log("[-] FAIL: bcrypt.compare not found (password verification).");
  }

  // 3) Cookie flags
  if (fileContains(serverContent, "httpOnly: true")) {
    console.log("[+] PASS: httpOnly: true set on session cookie.");
    total++;
  } else {
    console.log("[-] FAIL: httpOnly flag missing on session cookie.");
  }

  if (fileContains(serverContent, "secure: true")) {
    console.log("[+] PASS: secure: true set on session cookie.");
    total++;
  } else {
    console.log("[-] FAIL: secure flag missing on session cookie.");
  }

  if (fileContains(serverContent, "sameSite")) {
    console.log("[+] PASS: sameSite option defined on session cookie.");
    total++;
  } else {
    console.log("[-] FAIL: sameSite option missing on session cookie.");
  }

  // 4) Session rotation checks
  //   - Old predictable pattern username + "-" + Date.now() must be gone
  //   - crypto.randomBytes(...) should be used to generate tokens
  let rotationOk = true;

  if (fileNotContains(serverContent, "username + \"-\" + Date.now") &&
      fileNotContains(serverContent, "username + '-' + Date.now")) {
    console.log("[+] PASS: Predictable session token pattern (username + '-' + Date.now) removed.");
  } else {
    console.log("[-] FAIL: Predictable session token pattern (username + '-' + Date.now) still present.");
    rotationOk = false;
  }

  if (fileContains(serverContent, "crypto.randomBytes(")) {
    console.log("[+] PASS: crypto.randomBytes used for session/token generation (good entropy).");
  } else {
    console.log("[-] FAIL: crypto.randomBytes not found for token generation.");
    rotationOk = false;
  }

  if (rotationOk) {
    console.log("[+] PASS: Session rotation / secure token generation appears implemented.");
    total++;
  } else {
    console.log("[-] FAIL: Session rotation / secure token generation appears incomplete.");
  }

  // 5) Session expiration checks
  // We accept ANY of the following as evidence:
  //   - "expires" field in session object
  //   - cookie option "maxAge"
  //   - use of "Date.now()" plus a "+" (Date.now() + ...)
  let expirationOk = false;

  if (fileContains(serverContent, "expires") || fileContains(serverContent, "expiry")) {
    console.log("[+] PASS: 'expires'/'expiry' field found (possible session expiration).");
    expirationOk = true;
  }

  if (fileContains(serverContent, "maxAge")) {
    console.log("[+] PASS: 'maxAge' option found (possible cookie expiration).");
    expirationOk = true;
  }

  // Look for "Date.now() +"
  if (serverContent.match(/Date\.now\(\)\s*\+/)) {
    console.log("[+] PASS: Date.now() + ... pattern found (likely timeout calculation).");
    expirationOk = true;
  }

  if (expirationOk) {
    total++;
  } else {
    console.log("[-] FAIL: No clear indication of session expiration logic found.");
  }

  // 6) localStorage should NOT be used for session
  let localStoragePenalty = 0;
  if (fileContains(loginContent, "localStorage.setItem")) {
    console.log("[-] FAIL: login.html still uses localStorage.setItem for session/token storage.");
    localStoragePenalty = 1;
  } else {
    console.log("[+] PASS: localStorage.setItem removed from login.html.");
  }

  const score = total - localStoragePenalty;

  console.log("\n== RESULT ==");
  console.log(`Raw score (before localStorage penalty): ${total} / ${max}`);
  if (localStoragePenalty > 0) {
    console.log(`Penalty: -${localStoragePenalty} (localStorage usage)`);
  }
  console.log(`Final score: ${score} / ${max}`);

  if (score === max) {
    console.log("Status: PERFECT (all required checks passed).");
  } else if (score >= max - 2) {
    console.log("Status: GOOD (most checks passed).");
  } else {
    console.log("Status: INCOMPLETE (significant issues remain).");
  }
}

grade();
