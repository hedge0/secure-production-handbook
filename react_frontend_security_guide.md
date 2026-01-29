# React Frontend Security Guide

**Last Updated:** January 29, 2026

A practical guide focused on securing production React applications. React's built-in protections handle many common vulnerabilities (XSS), allowing this guide to focus on configuration, authentication patterns, and security pitfalls specific to modern React development.

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
   - [Required Tools](#required-tools)
   - [Recommended Frameworks](#recommended-frameworks)
   - [External Services](#external-services)
3. [React's Built-In Security](#3-reacts-built-in-security)
   - [Automatic XSS Prevention](#automatic-xss-prevention)
   - [When React DOESN'T Protect You](#when-react-doesnt-protect-you)
4. [Authentication & Session Management](#4-authentication--session-management)
   - [JWT Storage (Recommended Approach)](#jwt-storage-recommended-approach)
   - [Token Refresh Pattern](#token-refresh-pattern)
5. [Content Security Policy (CSP)](#5-content-security-policy-csp)
   - [Basic CSP Configuration](#basic-csp-configuration)
   - [CSP with Next.js](#csp-with-nextjs)
   - [CSP with Vite](#csp-with-vite)
6. [CSRF Protection](#6-csrf-protection)
   - [Understanding CSRF Attacks](#understanding-csrf-attacks)
   - [Defense: CSRF Tokens](#defense-csrf-tokens)
   - [Alternative: SameSite Cookies](#alternative-samesite-cookies)
7. [Dependency Security](#7-dependency-security)
   - [npm audit](#npm-audit)
   - [Dependabot](#dependabot)
   - [Avoiding Malicious Packages](#avoiding-malicious-packages)
   - [SAST with Semgrep or Opengrep](#sast-with-semgrep-or-opengrep)
   - [Secret Scanning with TruffleHog](#secret-scanning-with-trufflehog)
8. [Environment Variables & Secrets](#8-environment-variables--secrets)
   - [What NOT to Put in Frontend](#what-not-to-put-in-frontend)
   - [Safe Environment Variables](#safe-environment-variables)
   - [Backend-for-Frontend Pattern](#backend-for-frontend-pattern)
9. [Browser Security Headers](#9-browser-security-headers)
   - [Essential Security Headers](#essential-security-headers)
   - [Next.js Configuration](#nextjs-configuration)
   - [Nginx Configuration](#nginx-configuration)
10. [React-Specific Security Pitfalls](#10-react-specific-security-pitfalls)
    - [Dangerous Props](#dangerous-props)
    - [Third-Party Components](#third-party-components)
    - [React DevTools in Production](#react-devtools-in-production)
    - [Source Maps](#source-maps)
11. [Attack Scenarios Prevented](#11-attack-scenarios-prevented)
12. [References](#12-references)

## 1. Overview

React applications run in the browser and communicate with backend APIs. This guide focuses on securing the frontend while recognizing that **true security is enforced server-side**. React's built-in XSS protections handle most injection attacks, so this guide emphasizes authentication, CSP, and React-specific pitfalls.

**What React Already Handles:**

- XSS prevention (JSX auto-escapes by default)
- Safe rendering (strings escaped automatically)
- Protection against HTML injection

**What You Must Configure:**

- Authentication (JWT storage, token refresh)
- Content Security Policy
- CSRF tokens for state-changing requests
- Dependency security
- Proper secret management

**Core Principles:**

- **Use TypeScript**: Type safety catches security bugs at compile-time
- **Trust No Client**: All authorization happens server-side
- **Defense in Depth**: Multiple security layers (CSP + secure cookies + HTTPS)
- **Minimize Attack Surface**: Remove debug code, sanitize user content
- **Keep Dependencies Updated**: npm audit regularly
- **Fail Securely**: Redirect to login on auth errors

## 2. Prerequisites

### Required Tools

- [Node.js 18+](https://nodejs.org/) and npm/pnpm
- [React 18+](https://react.dev/)
- **[TypeScript](https://www.typescriptlang.org/)** - Strongly recommended over JavaScript (type safety catches security bugs at compile-time)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning (detects API keys, tokens in code)
- [Semgrep](https://semgrep.dev/) or [Opengrep](https://github.com/opengrep/opengrep) - SAST for JavaScript/TypeScript vulnerabilities
- [npm audit](https://docs.npmjs.com/cli/v9/commands/npm-audit) - Built-in dependency scanner

**TypeScript vs JavaScript:**

Use **TypeScript** for all production React applications:

- Catches type-related security bugs at compile-time (null checks, undefined access)
- Enforces type safety in API responses (prevents unexpected data shapes)
- Better IDE support for catching vulnerabilities (autocomplete prevents typos in security-critical code)
- Industry standard for serious production applications

**Only use JavaScript if:**

- Small prototype/demo (<1,000 lines)
- Learning React fundamentals
- Legacy codebase without migration resources

### Recommended Frameworks

This guide uses **React + Vite** for examples, but patterns apply to:

- Next.js (with additional server-side security)
- Create React App
- Remix
- Astro with React

### External Services

| Service            | Purpose                | Providers                                |
| ------------------ | ---------------------- | ---------------------------------------- |
| **Authentication** | JWT/session management | Auth0, Clerk, Firebase Auth, AWS Cognito |
| **API Backend**    | Authorization and data | Your API (see API Security Guide)        |
| **CDN**            | Static asset delivery  | CloudFlare, CloudFront, Fastly           |

## 3. React's Built-In Security

### Automatic XSS Prevention

React provides automatic XSS protection by escaping all values rendered in JSX expressions. When you render user input, React automatically converts HTML special characters to their safe equivalents.

```jsx
// SAFE - React escapes user input automatically
function UserProfile({ userName }) {
  return <div>Hello, {userName}</div>;
  // Even if userName = "<script>alert('xss')</script>"
  // React renders: Hello, &lt;script&gt;alert('xss')&lt;/script&gt;
}
```

**What React Does:**

- Escapes `<`, `>`, `&`, `"`, `'` in JSX expressions
- Prevents script execution in rendered content
- Sanitizes attributes (`href`, `src`, etc.)

This automatic escaping makes React applications inherently more secure than manual DOM manipulation where developers must remember to escape every user-controlled value.

### When React DOESN'T Protect You

React's automatic protections have critical gaps where developers must implement additional security:

**Dangerous pattern: dangerouslySetInnerHTML**

This prop bypasses React's XSS protection entirely. Never use it with user-controlled content without sanitization.

```jsx
// DANGEROUS - Bypasses React's protection
function UnsafeContent({ htmlContent }) {
  return <div dangerouslySetInnerHTML={{ __html: htmlContent }} />;
  // If htmlContent = "<img src=x onerror=alert('xss')>" - XSS executes!
}

// SAFE - Use DOMPurify for sanitization
import DOMPurify from "dompurify";

function SafeContent({ htmlContent }) {
  const clean = DOMPurify.sanitize(htmlContent);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

**When you need DOMPurify:**

- User-generated rich text (blog comments, WYSIWYG editors)
- Markdown-to-HTML conversion
- HTML from external APIs

Install: `npm install dompurify @types/dompurify`

**Dangerous: javascript: URLs**

React does not validate URL protocols. Malicious URLs like `javascript:alert('xss')` will execute when clicked.

```jsx
// DANGEROUS - javascript: URLs execute code
function UnsafeLink({ userUrl }) {
  return <a href={userUrl}>Click</a>;
}

// SAFE - Validate URLs before rendering
function SafeLink({ userUrl }) {
  const isSafe =
    userUrl.startsWith("http://") || userUrl.startsWith("https://");

  if (!isSafe) {
    return <span>Invalid link</span>;
  }

  return (
    <a href={userUrl} rel="noopener noreferrer">
      Click
    </a>
  );
}
```

Always validate user-provided URLs start with safe protocols. For internal navigation, use React Router's `<Link>` component.

## 4. Authentication & Session Management

### JWT Storage (Recommended Approach)

**Never store JWTs in localStorage or sessionStorage** - both are vulnerable to XSS attacks. Any JavaScript code (including malicious scripts) can read these storage mechanisms and steal tokens.

**Use HttpOnly cookies for authentication tokens.** HttpOnly cookies are not accessible to JavaScript, preventing XSS-based token theft. The browser automatically includes them with requests.

```typescript
// TypeScript example (RECOMMENDED for production)
interface User {
  id: string;
  email: string;
  name: string;
}

async function login(email: string, password: string): Promise<User> {
  const response = await fetch("https://api.example.com/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // Send/receive cookies
    body: JSON.stringify({ email, password }),
  });

  // Server sets: Set-Cookie: token=...; HttpOnly; Secure; SameSite=Strict

  if (!response.ok) throw new Error("Login failed");

  return response.json();
}

// Subsequent requests automatically include cookie
async function fetchUserData(): Promise<User> {
  const response = await fetch("https://api.example.com/user", {
    credentials: "include", // Sends HttpOnly cookie
  });

  if (!response.ok) throw new Error("Failed to fetch user data");

  return response.json();
}
```

**Backend cookie configuration:**

- `httpOnly: true` - JavaScript cannot access the cookie
- `secure: true` - Cookie only sent over HTTPS
- `sameSite: 'strict'` - Prevents CSRF attacks
- `maxAge: 15 * 60 * 1000` - Short expiration (15 minutes)

**Common JWT Storage Pitfall: Client-Side Decoding for UI State**

Many developers store JWTs in localStorage specifically to decode them client-side for displaying user info (name, email, role). This creates a false trade-off between security and convenience.

```typescript
// ❌ INSECURE - storing JWT in localStorage to access claims
const token = localStorage.getItem("jwt");
const decoded = JSON.parse(atob(token.split(".")[1])); // Decode JWT payload
const userName = decoded.name; // Extract user info

// Security issue: JWT accessible to XSS attacks
// If attacker injects script, they steal token and impersonate user
```

**The correct pattern:** Backend returns user info separately from auth token.

```typescript
// ✅ SECURE - token in HttpOnly cookie, user info returned separately
async function login(email: string, password: string): Promise<User> {
  const response = await fetch("https://api.example.com/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ email, password }),
  });

  // Backend sets HttpOnly cookie AND returns user object
  const user = await response.json();

  // Store user info in React state, not localStorage
  // JWT stays in secure HttpOnly cookie
  return user; // { id, email, name, role }
}

// Display user info from state/context, not by decoding JWT
function UserProfile() {
  const { user } = useAuth(); // From React Context/state
  return <div>Welcome, {user.name}!</div>; // No JWT decoding needed
}
```

Why this matters: Developers often think "I need the JWT claims for my UI, so I must store it in localStorage." But the backend can return user info as a regular JSON response while keeping the JWT in an HttpOnly cookie. Your React app gets all the data it needs for UI without exposing the authentication token to JavaScript.

The authentication flow: (1) User logs in, (2) Backend sets HttpOnly cookie with JWT, (3) Backend also returns user object in response body, (4) React stores user object in state/context for UI, (5) Subsequent API calls automatically include HttpOnly cookie, (6) XSS attacks can't access the JWT.

### Token Refresh Pattern

Short-lived access tokens (15 minutes) combined with longer-lived refresh tokens (7 days) provide security and convenience. If an access token is stolen, it expires quickly. The refresh token generates new access tokens without re-authentication.

```jsx
import { useState, useEffect } from "react";

function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();

    // Refresh token before expiration (every 14 minutes)
    const interval = setInterval(refreshToken, 14 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  async function checkAuth() {
    try {
      const response = await fetch("/api/auth/me", { credentials: "include" });
      if (response.ok) {
        setUser(await response.json());
      }
    } finally {
      setLoading(false);
    }
  }

  async function refreshToken() {
    try {
      await fetch("/api/auth/refresh", {
        method: "POST",
        credentials: "include",
      });
    } catch (error) {
      setUser(null); // Refresh failed - logout
    }
  }

  async function logout() {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "include",
    });
    setUser(null);
  }

  return { user, loading, logout };
}
```

**Why this is more secure:**

- Stolen access tokens expire in 15 minutes
- Refresh tokens can be revoked server-side
- Failed refresh attempts trigger security alerts
- User experience is seamless (auto-refresh in background)

## 5. Content Security Policy (CSP)

Content Security Policy provides defense-in-depth protection against XSS. Even if an attacker bypasses React's protections and injects malicious code, CSP prevents that code from executing by restricting which scripts the browser will run.

**How CSP works:** The server sends a `Content-Security-Policy` header telling the browser which sources are allowed for scripts, styles, images, and other resources. Unauthorized scripts are blocked.

### Basic CSP Configuration

**Essential directives for React applications:**

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
```

**What each directive does:**

- `default-src 'self'`: Only load resources from your own domain
- `script-src 'self'`: Only execute JavaScript from your domain (blocks inline scripts and external scripts)
- `style-src 'self' 'unsafe-inline'`: Allow CSS from your domain and inline styles (React uses inline styles)
- `connect-src 'self' https://api.example.com`: Restrict fetch/XHR to specific API endpoints
- `frame-ancestors 'none'`: Prevent your site from being embedded in iframes (clickjacking protection)

### CSP with Next.js

**next.config.js:**

```javascript
module.exports = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          {
            key: "Content-Security-Policy",
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-eval' 'unsafe-inline'", // Dev mode needs these
              "style-src 'self' 'unsafe-inline'",
              "connect-src 'self' https://api.example.com",
              "frame-ancestors 'none'",
            ].join("; "),
          },
        ],
      },
    ];
  },
};
```

### CSP with Vite

**Production (Nginx):**

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://api.example.com; frame-ancestors 'none';" always;
```

For Vite/CRA, configure via Nginx or CloudFlare Transform Rules (Settings → Transform Rules → Modify Response Header).

**Development vs Production:** Development environments often require relaxed CSP (`'unsafe-eval'`, `'unsafe-inline'`) for hot module reloading. Use environment detection to apply stricter CSP in production.

### Nonce-Based CSP Implementation

Nonce-based CSP is more secure than `'unsafe-inline'` for applications with third-party scripts. The server generates a unique random value per request and includes it in both the CSP header and script tags.

**Next.js Middleware:**

```typescript
// middleware.ts
import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";

export function middleware(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");

  const cspHeader = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' https://cdn.example.com`,
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self' https://api.example.com",
    "frame-ancestors 'none'",
  ].join("; ");

  const response = NextResponse.next();
  response.headers.set("Content-Security-Policy", cspHeader);
  response.headers.set("x-nonce", nonce);
  return response;
}
```

**Using Nonce in Components:**

```typescript
export const getServerSideProps = async ({ req }) => {
  return { props: { nonce: req.headers["x-nonce"] || "" } };
};

export default function Page({ nonce }) {
  return (
    <>
      {/* Inline script with nonce */}
      <script
        nonce={nonce}
        dangerouslySetInnerHTML={{
          __html: `console.log('Allowed by CSP');`,
        }}
      />

      {/* Third-party script with nonce */}
      <script nonce={nonce} src="https://analytics.example.com/script.js" />
    </>
  );
}
```

**Key Points:**

- Generate new nonce per request (never reuse)
- Use `crypto.randomUUID()` or `crypto.randomBytes(16)`
- Pass nonce to all components that need inline scripts
- Add third-party CDN domains to `script-src` or use nonce
- Use `'unsafe-inline'` in development only (breaks with nonces)

**CSP Violation Reporting:**

```typescript
// Add to CSP header
"report-uri https://your-domain.com/api/csp-report";

// Log violations
app.post("/api/csp-report", (req, res) => {
  console.log("CSP Violation:", req.body);
  res.status(204).end();
});
```

Test with `Content-Security-Policy-Report-Only` first, then switch to enforcing mode after fixing violations.

## 6. CSRF Protection

### Understanding CSRF Attacks

Cross-Site Request Forgery (CSRF) exploits the browser's automatic inclusion of cookies with every request. If your application uses cookie-based authentication and a user visits a malicious website while logged in, the attacker's site can trigger authenticated requests without the user's knowledge.

**Example attack scenario:**

```html
<!-- Attacker's website -->
<form action="https://yourbank.com/transfer" method="POST">
  <input name="to" value="attacker" />
  <input name="amount" value="1000" />
</form>
<script>
  document.forms[0].submit();
</script>
```

If the user is logged into yourbank.com, the browser automatically includes the authentication cookie with the request, executing the transfer.

**When CSRF protection is required:**

- Your API uses cookie-based authentication
- Your API has state-changing endpoints (POST, PUT, DELETE)
- Your API accepts requests from browser-based clients

### Defense: CSRF Tokens

Backend generates random token and stores in session. Frontend includes token in request headers for state-changing operations. Backend validates token matches session.

```jsx
function useCSRF() {
  const [csrfToken, setCSRFToken] = useState("");

  useEffect(() => {
    fetch("/api/csrf-token", { credentials: "include" })
      .then((r) => r.json())
      .then((data) => setCSRFToken(data.csrfToken));
  }, []);

  return csrfToken;
}

function TransferForm() {
  const csrfToken = useCSRF();

  async function handleSubmit(e) {
    e.preventDefault();
    await fetch("/api/transfer", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken, // Include token in header
      },
      body: JSON.stringify({ to, amount }),
    });
  }

  return <form onSubmit={handleSubmit}>{/* form fields */}</form>;
}
```

### Alternative: SameSite Cookies

Modern browsers support `SameSite` cookie attribute which prevents cookies from being sent in cross-site requests.

```javascript
// Backend sets SameSite cookie
res.cookie("token", jwt, {
  httpOnly: true,
  secure: true,
  sameSite: "strict", // or 'lax'
});
```

**SameSite options:**

- `Strict`: Cookie never sent on cross-site requests (strongest protection, may break legitimate flows)
- `Lax`: Cookie sent on top-level navigation (GET only), blocked on form submissions and fetch requests

**Recommendation:** Use `SameSite=Lax` as primary defense + verify `Origin` header as backup. Add CSRF tokens for extra-sensitive operations (financial transactions, account changes).

## 7. Dependency Security

Vulnerable dependencies are one of the most common security issues in React applications. Third-party packages can contain known security flaws that attackers actively exploit, and malicious packages can be intentionally uploaded to npm with names similar to popular libraries (typosquatting). This section covers tools and practices to identify and prevent dependency vulnerabilities.

### npm audit

npm audit scans your `package.json` and `package-lock.json` against the npm registry's vulnerability database. It identifies packages with known security issues and provides information about severity levels and available patches.

**Run regularly:**

```bash
# Check for vulnerabilities
npm audit

# Fix automatically (may break things)
npm audit fix

# View detailed report
npm audit --json
```

**Severity levels:**

- **Critical/High**: Immediate action required - exploitable vulnerabilities that can compromise your application
- **Moderate**: Address in next release cycle - potential security issues with lower exploitability
- **Low**: Address when convenient - minor issues or unlikely attack scenarios

**CI/CD integration:**

```yaml
# GitHub Actions
- name: Security audit
  run: npm audit --audit-level=high
```

Run `npm audit --audit-level=high` in your CI/CD pipeline to fail builds with critical or high severity vulnerabilities. This prevents vulnerable code from reaching production.

**Important limitation:** npm audit only detects _known_ vulnerabilities with published CVEs. It cannot detect zero-day vulnerabilities or malicious code in packages without reported security issues.

### Dependabot

Dependabot automatically monitors your dependencies and creates pull requests when new versions are released, including security patches. This is particularly valuable because it catches vulnerabilities as soon as they're disclosed, often before developers manually check for updates.

**Enable in GitHub:**

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

Dependabot's continuous monitoring means you don't need to remember to check for updates manually. Configure it to check weekly for most projects, or daily for security-critical applications. The `open-pull-requests-limit` prevents overwhelming your team with too many simultaneous PRs.

**Best practice:** Enable automatic security updates for patch and minor versions (these rarely break compatibility), but manually review major version updates for breaking changes.

### Avoiding Malicious Packages

Beyond vulnerable packages, the npm ecosystem contains malicious packages designed to steal credentials or inject backdoors. Typosquatting attacks use package names with small typos (e.g., `reacct` instead of `react`) hoping developers will install them by mistake.

**Typosquatting defense:**

```bash
# Check package before installing
npm view package-name

# Verify publisher
npm view react dist.tarball

# Use package-lock.json (commit to git)
npm ci  # In CI/CD (uses lock file)
```

**Before installing any package, check:**

1. **Download count** - Legitimate packages typically have >100k weekly downloads
2. **Last updated date** - Recently maintained packages indicate active development
3. **Publisher reputation** - Verified publishers or official organizations are safer
4. **GitHub stars/issues** - Active community engagement suggests trustworthiness
5. **Source code** - For critical dependencies, review the actual code

**Lock file prevents:**

- Malicious version bumps
- Supply chain attacks
- Dependency confusion

The `package-lock.json` file locks your dependencies to specific versions and checksums. Use `npm ci` in CI/CD environments instead of `npm install` to ensure the exact versions from the lock file are installed, preventing attackers from injecting malicious updates between development and production.

**Supply chain attack patterns to watch for:**

Recent attacks demonstrate how npm supply chain compromises occur:

- **Ownership transfer attacks**: Popular unmaintained packages transferred to malicious actors who inject backdoors in minor updates (e.g., event-stream 2018 - 2M downloads/week, injected cryptocurrency wallet stealer)
- **Account compromise**: Maintainer accounts stolen via phishing, malicious versions published (e.g., ua-parser-js 2021 - 9M downloads/week, deployed cryptominers)
- **Dependency confusion**: Attackers publish malicious packages with same name as internal private packages, npm installs public version (e.g., targeting tech companies' internal tools)

**Post-install script risks:**

```bash
# Check if package runs code during install
npm view package-name scripts

# Disable auto-execution (run manually after audit)
npm install --ignore-scripts
```

Many packages run arbitrary code during `npm install` via post-install scripts. A malicious package can steal environment variables (often containing CI/CD secrets), modify other packages in node_modules, or establish persistence. Review scripts before allowing execution, especially for new dependencies.

**Advanced protection:**

- Use tools like Socket Security that analyze package behavior (network requests, file system access, shell commands)
- Enable GitHub Dependabot security alerts for automatic vulnerability notifications
- For security-critical projects, vendor key dependencies (copy source into your repo) to isolate from supply chain

### SAST with Semgrep or Opengrep

Static Application Security Testing (SAST) analyzes your source code for security vulnerabilities without executing it. Unlike dependency scanning which only checks for known vulnerable packages, SAST examines your actual code patterns to find security flaws like XSS, hardcoded secrets, and injection vulnerabilities.

Scan JavaScript/TypeScript code for security vulnerabilities.

**Semgrep vs Opengrep:**

- **[Semgrep](https://semgrep.dev/)** (Paid): AI-powered analysis reduces false positives significantly, better accuracy
- **[Opengrep](https://github.com/opengrep/opengrep)** (Free): Open-source fork, community rules, more false positives

**Recommendation:** Use Semgrep if budget allows (cleaner signal). Use Opengrep for cost-conscious teams.

**Installation:**

```bash
# Semgrep
pip install semgrep

# Opengrep (same CLI)
pip install opengrep
# or use Docker: docker pull opengrep/opengrep
```

**Run security scans:**

```bash
# Scan with security rules (works with both semgrep and opengrep)
semgrep --config=auto src/
# or: opengrep --config=auto src/

# CI-specific security rules
semgrep --config="p/security-audit" --config="p/react" src/

# JSON output for CI/CD
semgrep --config=auto --json -o results.json src/
```

**GitHub Actions Integration:**

```yaml
# .github/workflows/semgrep.yml
name: Semgrep

on:
  pull_request: {}
  push:
    branches: [main]

jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      # Option 1: Semgrep (paid, fewer false positives)
      - uses: semgrep/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/react
            p/javascript

      # Option 2: Opengrep (free, more false positives)
      # - run: pip install opengrep
      # - run: opengrep --config=auto src/
```

Run SAST in your CI/CD pipeline to block pull requests containing security vulnerabilities. Configure it to fail builds on high-severity findings while logging moderate/low findings for review.

**What Semgrep/Opengrep Catches:**

- XSS vulnerabilities (dangerouslySetInnerHTML misuse)
- Hardcoded secrets in code
- SQL injection patterns
- Command injection
- Insecure randomness
- Path traversal vulnerabilities

### Secret Scanning with TruffleHog

TruffleHog scans git repositories for accidentally committed secrets (API keys, credentials, tokens). Unlike SAST which finds code patterns, TruffleHog specifically looks for high-entropy strings and known secret formats. It detects hundreds of secret types including AWS keys, database credentials, and private keys.

Prevent API keys and secrets from being committed to git.

**Pre-commit Hook:**

```bash
# Install TruffleHog
pip install trufflehog

# Add to .git/hooks/pre-commit
#!/bin/bash
trufflehog filesystem . --fail --no-update
```

Installing TruffleHog as a pre-commit hook blocks secrets from ever entering your repository. The hook runs before each commit and rejects the commit if secrets are detected, forcing developers to remove them before code is versioned.

**Scan entire git history:**

```bash
# Scan all commits for secrets
trufflehog git file://. --since-commit HEAD~100

# Scan specific files
trufflehog filesystem src/ --fail
```

**GitHub Actions Integration:**

```yaml
# .github/workflows/secrets.yml
name: Secret Scan

on: [push, pull_request]

jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: TruffleHog
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
```

Run TruffleHog in CI/CD to catch secrets that bypassed pre-commit hooks (e.g., commits made with `--no-verify`) or were committed before TruffleHog was installed. The `fetch-depth: 0` ensures the entire git history is scanned.

**What TruffleHog Detects:**

- AWS keys (ACCESS_KEY_ID, SECRET_ACCESS_KEY)
- API keys (Stripe, Twilio, SendGrid, etc.)
- Database connection strings
- JWT secrets
- Private keys (RSA, SSH)
- OAuth tokens

**Prevention:**

```bash
# Add to .gitignore
.env
.env.local
.env.*.local
secrets/
*.pem
*.key
```

**Critical reminder:** Once secrets are committed to git, they must be considered compromised even after removal. Git history preserves deleted content, so attackers with repository access can retrieve historical commits. If a secret is accidentally committed, immediately rotate it (generate new credentials and revoke the old ones).

## 8. Environment Variables & Secrets

**Critical principle: Frontend code is PUBLIC.** Anyone can view source, inspect network requests, and decompile your JavaScript bundles. All frontend code, including environment variables bundled into your application during build time, is accessible to users. This fundamental reality shapes how you must handle secrets in React applications.

### What NOT to Put in Frontend

**NEVER in frontend code:**

- Database credentials
- API secret keys
- Private encryption keys
- OAuth client secrets

**Frontend code is PUBLIC** (users can view source).

Environment variables in React applications (those prefixed with `VITE_`, `REACT_APP_`, or `NEXT_PUBLIC_`) are embedded into your JavaScript bundle during build time. When you run `npm run build`, these values are replaced with their actual strings in the compiled code. Anyone can open browser dev tools, look at your JavaScript files, and extract these values. This is why you must never store secrets in frontend environment variables.

**What's safe for frontend:**

- **API URLs** - If your API is publicly accessible anyway (e.g., `https://api.yourapp.com`)
- **Public API keys** - Keys specifically designed for client-side use (Stripe publishable keys starting with `pk_`, Google Maps API keys with domain restrictions)
- **Analytics IDs** - Google Analytics, Segment tracking IDs
- **Feature flags** - Boolean values controlling UI features
- **Environment identifiers** - Strings like "production" or "staging"

The key distinction: public keys are designed to be exposed and have built-in protections (domain restrictions, rate limiting), while secret keys provide write access or administrative privileges.

### Safe Environment Variables

**Vite:**

```bash
# .env (NOT committed to git)
VITE_API_URL=https://api.example.com
VITE_STRIPE_PUBLIC_KEY=pk_test_...
```

```jsx
// Safe - public keys only
const apiUrl = import.meta.env.VITE_API_URL;
const stripeKey = import.meta.env.VITE_STRIPE_PUBLIC_KEY;
```

**Create React App:**

```bash
REACT_APP_API_URL=https://api.example.com
```

```jsx
const apiUrl = process.env.REACT_APP_API_URL;
```

Environment variables without the framework-specific prefix (`VITE_`, `REACT_APP_`, `NEXT_PUBLIC_`) are NOT included in frontend builds. This provides an additional safety layer - if you accidentally reference a secret variable, the build will fail with an undefined error rather than exposing the secret.

**Important:** Even though `.env` files aren't committed to git (add them to `.gitignore`), the variables they contain are still embedded in your production JavaScript bundle. The `.env` file protects secrets during development, but doesn't prevent them from appearing in built code if they use the public prefix.

### Backend-for-Frontend Pattern

Never call third-party APIs directly from your frontend with secret keys. Instead, create backend endpoints that accept requests from your authenticated frontend, validate them, and then call third-party services using server-side secrets.

**NEVER call third-party APIs directly from frontend with your secret keys.**

**Bad: Exposes secret API key**

```jsx
// WRONG - Secret key exposed to all users
const stripe = Stripe("sk_live_SECRET_KEY_HERE");
await stripe.charges.create({ amount: 1000 });
```

**Good: Proxy through your backend**

```jsx
// Frontend - calls your backend
async function createCharge(amount) {
  return fetch("/api/payments/charge", {
    method: "POST",
    credentials: "include",
    body: JSON.stringify({ amount }),
  });
}

// Backend API route - holds the secret
app.post("/api/payments/charge", authenticateUser, async (req, res) => {
  const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

  const charge = await stripe.charges.create({
    amount: req.body.amount,
    currency: "usd",
    customer: req.user.stripeCustomerId,
  });

  res.json(charge);
});
```

This pattern applies to all services requiring authentication: payment processing (Stripe, PayPal), email (SendGrid, Mailgun), SMS (Twilio), cloud storage (AWS S3 uploads), and any other API requiring secret credentials.

**Benefits of Backend-for-Frontend:**

- Secrets never leave your server
- User authentication can be enforced (the `authenticateUser` middleware)
- Request validation and sanitization in one place
- Rate limiting to prevent abuse
- Audit logging for compliance
- Ability to modify third-party API calls without redeploying frontend

## 9. Browser Security Headers

Security headers instruct browsers on how to handle your web application, providing defense-in-depth protection that works independently of your React code. Even if vulnerabilities exist in your application, properly configured headers can significantly mitigate their impact by controlling browser behavior at a fundamental level.

### Essential Security Headers

Configure these headers in production to provide defense-in-depth protection:

**Core headers every React app needs:**

- `X-Frame-Options`: Prevents clickjacking
- `X-Content-Type-Options`: Prevents MIME sniffing
- `Strict-Transport-Security`: Enforces HTTPS
- `Referrer-Policy`: Controls referrer information
- `Permissions-Policy`: Disables unnecessary browser features

These headers are set by your web server (Nginx, Apache) or framework (Next.js) and sent with every HTTP response. Browsers read these headers and enforce the specified security policies regardless of what your JavaScript code does.

### Next.js Configuration

**next.config.js:**

```javascript
module.exports = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          {
            key: "X-Frame-Options",
            value: "DENY",
          },
          {
            key: "X-Content-Type-Options",
            value: "nosniff",
          },
          {
            key: "Referrer-Policy",
            value: "strict-origin-when-cross-origin",
          },
          {
            key: "Strict-Transport-Security",
            value: "max-age=31536000; includeSubDomains",
          },
          {
            key: "Permissions-Policy",
            value: "geolocation=(), microphone=(), camera=()",
          },
        ],
      },
    ];
  },
};
```

Next.js configuration allows you to set headers programmatically. The `source: "/:path*"` pattern applies these headers to all routes in your application.

### Nginx Configuration

For Vite, Create React App, or other frameworks without built-in header configuration, set headers in your reverse proxy or web server.

**nginx.conf:**

```nginx
# Prevent clickjacking
add_header X-Frame-Options "DENY" always;

# Prevent MIME sniffing
add_header X-Content-Type-Options "nosniff" always;

# Enable XSS filter (legacy browsers)
add_header X-XSS-Protection "1; mode=block" always;

# Enforce HTTPS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Control referrer
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions policy
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

The `always` parameter ensures headers are sent even for error responses (4xx, 5xx), which is important because error pages can also be vulnerable to attacks.

**CloudFlare (Transform Rules):**

CloudFlare can add headers via Transform Rules in dashboard (Settings → Transform Rules → Modify Response Header).

For applications behind CloudFlare or other CDNs, you can set headers at the CDN level, which takes effect before requests even reach your server. This provides protection even if your origin server is misconfigured.

### Headers Explained

**X-Frame-Options: DENY**

Prevents your site from being embedded in iframes, protecting against clickjacking attacks. Clickjacking tricks users into clicking malicious elements by overlaying transparent iframes over legitimate content. `DENY` blocks all iframe embedding; use `SAMEORIGIN` if you need to embed your own pages in iframes.

**X-Content-Type-Options: nosniff**

Prevents browsers from MIME-sniffing responses, forcing them to respect the declared `Content-Type` header. Without this, browsers might interpret a JavaScript file as HTML or vice versa based on content analysis, enabling certain XSS attacks where attackers upload malicious files with incorrect extensions.

**Strict-Transport-Security (HSTS)**

Forces browsers to always use HTTPS for all future requests to your domain for one year (`max-age=31536000` seconds). This prevents SSL-stripping attacks where attackers downgrade connections from HTTPS to unencrypted HTTP. The `includeSubDomains` directive applies this to all subdomains as well. Once set, browsers will refuse to connect via HTTP even if the user explicitly types `http://` in the address bar.

**Referrer-Policy: strict-origin-when-cross-origin**

Controls what referrer information browsers send with requests. `strict-origin-when-cross-origin` sends only the origin (domain) for cross-origin requests while sending the full URL for same-origin requests. This balances privacy (external sites don't see your full URLs) with analytics needs (your own analytics can track full paths). More restrictive policies like `no-referrer` provide better privacy but break some analytics and security features.

**Permissions-Policy: geolocation=(), microphone=(), camera=()**

Disables browser features your application doesn't use. Even if malicious injected scripts try to access the camera, microphone, or location, the browser will block these requests at the API level. This implements the principle of least privilege - only enable features your application actually needs. For applications that do need these features, specify allowed origins: `camera=(self), microphone=(self)`.

**Testing your configuration:**

Visit securityheaders.com with your production URL to verify all headers are properly set and receive a security grade. This free tool checks for missing or misconfigured headers and explains their security implications.

## 10. React-Specific Security Pitfalls

Beyond React's automatic protections and the configuration discussed in previous sections, several React-specific patterns and development practices require careful security consideration. These pitfalls often arise from convenience features or development tools that can introduce vulnerabilities if not properly managed in production.

### Dangerous Props

React does not validate URL protocols in props like `href`, `src`, or `formAction`. While React escapes the content, it doesn't prevent dangerous JavaScript execution through special URL protocols.

**Never pass user input to dangerous props:**

```jsx
// DANGEROUS - href can be javascript:
<a href={userInput}>Click</a>;

// SAFE - Validate first
function SafeLink({ href }) {
  if (!href.startsWith("http://") && !href.startsWith("https://")) {
    return null;
  }
  return (
    <a href={href} rel="noopener noreferrer">
      Link
    </a>
  );
}
```

Malicious URLs can use `javascript:alert('xss')` protocol to execute code when clicked, or `data:text/html,<script>alert('xss')</script>` to render arbitrary HTML. Always validate that user-provided URLs start with safe protocols before rendering them. For internal navigation within your React app, use React Router's `<Link>` component which doesn't support dangerous protocols.

The `rel="noopener noreferrer"` attribute prevents the linked page from accessing your page's `window.opener` object, protecting against tab-nabbing attacks where malicious sites use JavaScript to redirect your page.

### Third-Party Components

Third-party React components introduce code you don't control into your application. A malicious or compromised component library can steal user data, inject tracking scripts, or create backdoors.

**Audit before using:**

```bash
# Check downloads and github stars
npm view react-some-package

# Check for known vulnerabilities
npm audit
```

**Prefer:**

- Well-maintained packages (recent commits)
- High download counts (>100k/week)
- Official or trusted publishers

Before adding any third-party component:

1. **Check npm weekly downloads** - Popular packages (>100k/week) have been reviewed by many developers
2. **Review GitHub activity** - Recent commits and responsive maintainers suggest security consciousness
3. **Check the publisher** - Official organizations or verified individuals are safer than unknown accounts
4. **Scan for vulnerabilities** - Run `npm audit` after installation
5. **Review the code** - For security-critical components, read the actual source to understand what it does

Popular, well-maintained component libraries (Material-UI, Ant Design, Chakra UI, Radix UI) have security teams and established vulnerability disclosure processes. Newer or niche libraries may not have undergone security review. Be especially cautious with components that handle sensitive data (payment forms, authentication UI, file uploads).

### React DevTools in Production

React DevTools and debug code can expose application internals, component state, and sensitive user data. Development builds include extensive debugging information in the browser's React DevTools extension, allowing inspection of component props, state, and hooks.

**Remove in production builds:**

```javascript
// Vite automatically excludes devtools in production

// Verify:
if (import.meta.env.PROD) {
  console.log("Production mode - DevTools disabled");
}
```

Modern build tools (Vite, Next.js, Create React App) automatically exclude development-specific code in production builds through the `NODE_ENV=production` environment variable. However, verify this is working by checking your production JavaScript bundle - search for `__REACT_DEVTOOLS_GLOBAL_HOOK__` which should not appear in production code.

Additionally, remove or guard all `console.log` statements that might leak sensitive information. Use environment checks to conditionally enable debugging:

```jsx
if (import.meta.env.DEV) {
  console.log("Debug info:", userData);
}
```

### Source Maps

Source maps allow developers to debug minified production code by mapping it back to the original source. However, they also expose your application's source code, business logic, API keys hidden in code, and security implementations to anyone who can access them.

**Don't expose in production:**

```javascript
// vite.config.js
export default {
  build: {
    sourcemap: false, // Don't generate source maps
  },
};
```

**Options for balancing security and debuggability:**

1. **No source maps** (`sourcemap: false`): Most secure but makes production debugging difficult
2. **Hidden source maps** (`sourcemap: 'hidden'`): Generates `.map` files but doesn't reference them in JavaScript - upload to error tracking services (Sentry, Rollbar) that serve them only to authenticated developers
3. **Inline source maps**: Never use in production - embeds entire source code directly in JavaScript files

For most applications, hidden source maps with error tracking service integration provide the best balance. The maps exist for debugging but aren't publicly accessible through your web server.

If you need source maps for error tracking:

```javascript
// Upload to error tracking service (Sentry, etc)
// Serve source maps only to authenticated error tracking service
sourcemap: "hidden"; // Generates maps but doesn't link in JS
```

Error tracking services like Sentry can automatically upload your source maps during deployment and use them to de-minify error stack traces. The maps are stored on Sentry's servers with authentication required, so they never reach end users.

## 11. Attack Scenarios Prevented

**XSS (Cross-Site Scripting)**

- Attack: Inject `<script>alert('xss')</script>` in user input
- Mitigated by: React auto-escaping, DOMPurify for rich content, CSP

**CSRF (Cross-Site Request Forgery)**

- Attack: Attacker tricks user into making authenticated request
- Mitigated by: CSRF tokens, SameSite cookies, verify Origin header

**Clickjacking**

- Attack: Embed your site in invisible iframe, trick user into clicking
- Mitigated by: X-Frame-Options: DENY, CSP frame-ancestors

**Dependency Vulnerabilities**

- Attack: Malicious npm package or vulnerable dependency
- Mitigated by: npm audit, Dependabot, package-lock.json

**Token Theft (XSS → Steal localStorage)**

- Attack: XSS steals JWT from localStorage
- Mitigated by: HttpOnly cookies (not accessible to JavaScript)

**MITM (Man-in-the-Middle)**

- Attack: Intercept HTTP traffic, steal tokens
- Mitigated by: HTTPS only, HSTS header

**Open Redirect**

- Attack: `<a href={userInput}>` redirects to phishing site
- Mitigated by: URL validation, allowlist domains

**Supply Chain Attack**

- Attack: Typosquatted package or compromised dependency
- Mitigated by: Verify packages, use lock file, Dependabot alerts

**Sensitive Data in Frontend**

- Attack: API keys in frontend code extracted by viewing source
- Mitigated by: Only public keys in frontend, secrets in backend

**Session Fixation**

- Attack: Attacker sets user's session ID
- Mitigated by: Regenerate session on login, HttpOnly secure cookies

## 12. References

### React Security

- [React Security Best Practices](https://react.dev/learn/security)
- [React Security Docs](https://legacy.reactjs.org/docs/dom-elements.html#dangerouslysetinnerhtml)
- [TypeScript](https://www.typescriptlang.org/)

### Security Tools

- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Semgrep](https://semgrep.dev/)
- [Opengrep](https://github.com/opengrep/opengrep)
- [Dependabot](https://github.com/dependabot)
- [npm audit](https://docs.npmjs.com/cli/v9/commands/npm-audit)
- [DOMPurify](https://github.com/cure53/DOMPurify)

### Web Security Standards

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [SameSite Cookies](https://web.dev/samesite-cookies-explained/)
- [OWASP Frontend Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)

### Authentication

- [Auth0](https://auth0.com/)
- [Clerk](https://clerk.dev/)
- [Firebase Auth](https://firebase.google.com/docs/auth)
- [AWS Cognito](https://aws.amazon.com/cognito/)

### Security Testing

- [SecurityHeaders.com](https://securityheaders.com/)
- [Mozilla Observatory](https://observatory.mozilla.org/)
