# React Frontend Security Guide

**Last Updated:** September 22, 2026

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
   - [Don't Gate Auth in Middleware Alone (CVE-2025-29927)](#dont-gate-auth-in-middleware-alone-cve-2025-29927)
5. [Content Security Policy (CSP)](#5-content-security-policy-csp)
   - [Basic CSP Configuration](#basic-csp-configuration)
   - [CSP with Next.js](#csp-with-nextjs)
   - [CSP with Vite](#csp-with-vite)
   - [Nonce-Based CSP Implementation](#nonce-based-csp-implementation)
6. [CSRF Protection](#6-csrf-protection)
   - [Understanding CSRF Attacks](#understanding-csrf-attacks)
   - [Defense: CSRF Tokens](#defense-csrf-tokens)
   - [Alternative: SameSite Cookies](#alternative-samesite-cookies)
7. [Dependency Security](#7-dependency-security)
   - [npm audit](#npm-audit)
   - [Dependabot](#dependabot)
   - [Avoiding Malicious Packages](#avoiding-malicious-packages)
   - [2025 npm Supply-Chain Attacks and What Changed](#2025-npm-supply-chain-attacks-and-what-changed)
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
   - [Headers Explained](#headers-explained)
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

- [Node.js 22 LTS or later](https://nodejs.org/en) (24 LTS recommended; 18 and 20 are end-of-life) and npm/pnpm
- [React 19+](https://react.dev/) (React 18 does not block `javascript:` URLs). Using Server Components or Server Functions (e.g. Next.js App Router)? Stay on the latest patch of your 19.x line: 19.0.0-19.2.0 carry an unauthenticated RCE (CVE-2025-55182, CVSS 10.0)
- **[TypeScript](https://www.typescriptlang.org/)** - Strongly recommended over JavaScript (type safety catches security bugs at compile-time)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning (detects API keys, tokens in code)
- [Semgrep](https://semgrep.dev/), [Opengrep](https://github.com/opengrep/opengrep) or [Aikido Security](https://www.aikido.dev/) - SAST for JavaScript/TypeScript vulnerabilities
- [npm audit](https://docs.npmjs.com/cli/commands/npm-audit) - Built-in dependency scanner

**TypeScript vs JavaScript:**

Use **TypeScript** for all production React applications:

- Catches type-related security bugs at compile-time (null checks, undefined access)
- Documents API response shapes (types are erased at runtime, so validate untrusted responses with a schema library such as Zod before trusting them)
- Better IDE support for catching vulnerabilities (autocomplete prevents typos in security-critical code)
- Industry standard for serious production applications

**Only use JavaScript if:**

- Small prototype/demo (<1,000 lines)
- Learning React fundamentals
- Legacy codebase without migration resources

### Recommended Frameworks

This guide uses **React + Vite** for examples, but patterns apply to:

- Next.js (with additional server-side security)
- Legacy Create React App apps (CRA was deprecated in February 2025; migrate to Vite or a framework)
- React Router v7 framework mode (successor to Remix v2)
- Astro with React

### External Services

| Service            | Purpose                | Providers                                |
| ------------------ | ---------------------- | ---------------------------------------- |
| **Authentication** | JWT/session management | Auth0, Clerk, Firebase Auth, AWS Cognito |
| **API Backend**    | Authorization and data | Your API (see API Security Guide)        |
| **CDN**            | Static asset delivery  | Cloudflare, CloudFront, Fastly           |

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
- Neutralizes `javascript:` URLs in `href`, `src`, `action` and `formAction` (React 19+ only; React 18 just logs a dev warning). No version validates other schemes or where a link goes

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

Install: `npm install dompurify` (DOMPurify 3.2+ ships its own TypeScript types; `@types/dompurify` is a deprecated stub)

**Dangerous: javascript: and data: URLs**

React escapes text, not URL schemes. React 18 renders `<a href={userUrl}>` as-is, so `javascript:alert('xss')` runs when clicked; React 19 blocks `javascript:` URLs in JSX but allows every other scheme and cannot protect `window.location` or `window.open`. Validate the scheme on every version; the full pattern is in [Dangerous Props](#dangerous-props) under section 10.

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
- `sameSite: 'strict'` - Cookie is not sent on cross-site requests (a CSRF layer; see §6 for its limits)
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

```tsx
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
      const response = await fetch("/api/auth/refresh", {
        method: "POST",
        credentials: "include",
      });
      if (!response.ok) setUser(null); // fetch() resolves on 401 - only network errors throw
    } catch (error) {
      setUser(null); // Network failure - logout
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
- Refresh tokens can be revoked server-side (store them, or their IDs, on the server)
- Rotate the refresh token on every use and revoke the session when an old one is replayed (RFC 9700 §4.14.2); alert on that reuse
- User experience is seamless (auto-refresh in background)

### Don't Gate Auth in Middleware Alone (CVE-2025-29927)

In March 2025 Next.js patched CVE-2025-29927 (12.3.5, 13.5.9, 14.2.25, 15.2.3): any request carrying a crafted `x-middleware-subrequest` header skipped `middleware.ts` entirely, so every self-hosted app (`next start`, `output: 'standalone'`) whose only login check lived there was open to anonymous access. Vercel's postmortem is blunt: "We do not recommend Middleware to be the sole method of protecting routes in your application." Next.js 16 renamed the file to `proxy.ts` and calls it a last resort.

Treat middleware as a convenience redirect, not a security boundary. Verify the session inside every Route Handler, Server Component and Server Action that touches protected data; the check runs in the same process as the data access, so there is no header to spoof around it.

```typescript
// app/api/orders/route.ts - the check lives next to the data, not in middleware
import { getSession } from "@/lib/auth";
import { listOrders } from "@/lib/orders";

export async function GET() {
  const session = await getSession(); // reads the HttpOnly cookie server-side
  if (!session) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  return Response.json(await listOrders(session.userId));
}
```

## 5. Content Security Policy (CSP)

Content Security Policy provides defense-in-depth protection against XSS. Even if an attacker bypasses React's protections and injects malicious code, CSP prevents that code from executing by restricting which scripts the browser will run.

**How CSP works:** The server sends a `Content-Security-Policy` header telling the browser which sources are allowed for scripts, styles, images, and other resources. Unauthorized scripts are blocked.

### Basic CSP Configuration

**Essential directives for React applications:**

```http
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
- `style-src 'self' 'unsafe-inline'`: Allow CSS from your domain plus inline `<style>` tags and `style=""` markup. Client-rendered React `style={{...}}` props go through the CSSOM and are not blocked; you need `'unsafe-inline'` (or a nonce) for server-rendered `style` attributes and CSS-in-JS libraries that inject `<style>` tags
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
              // Without nonces, Next.js needs 'unsafe-inline' for its own inline scripts (weak XSS protection).
              // 'unsafe-eval' is dev-only. For a strict policy, use the nonce-based proxy below INSTEAD of this header.
              `script-src 'self' 'unsafe-inline'${process.env.NODE_ENV === "development" ? " 'unsafe-eval'" : ""}`,
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

For Vite (or legacy CRA) builds, configure via Nginx or Cloudflare Response Header Transform Rules (Rules → Overview → Create rule → Response Header Transform Rule).

**Development vs Production:** Development environments often require relaxed CSP (`'unsafe-eval'`, `'unsafe-inline'`) for hot module reloading. Use environment detection to apply stricter CSP in production.

### Nonce-Based CSP Implementation

Nonce-based CSP is more secure than `'unsafe-inline'` for applications with third-party scripts. The server generates a unique random value per request and includes it in both the CSP header and script tags.

**Next.js Proxy (`proxy.ts`; on Next.js 15 the same code lives in `middleware.ts` and exports `middleware`):**

```typescript
// proxy.ts
import { NextRequest, NextResponse } from "next/server";

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64"); // Web Crypto global, no import
  const isDev = process.env.NODE_ENV === "development";

  const cspHeader = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "connect-src 'self' https://api.example.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join("; ");

  // Set on the REQUEST headers: that is how server components (and Next.js itself) read the nonce
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", cspHeader);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", cspHeader); // browser copy
  return response;
}
```

Next.js parses the nonce out of the CSP request header and attaches it to its own framework and hydration scripts automatically. For your own scripts, read it in a server component:

**Using Nonce in Components:**

```tsx
// app/layout.tsx (server component)
import { headers } from "next/headers";
import Script from "next/script";

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const nonce = (await headers()).get("x-nonce") ?? "";

  return (
    <html lang="en">
      <body>
        {children}
        {/* Third-party script: nonce is what allows it, 'strict-dynamic' trusts what it loads */}
        <Script
          src="https://analytics.example.com/script.js"
          strategy="afterInteractive"
          nonce={nonce}
        />
      </body>
    </html>
  );
}
```

Pages Router: pass `nonce` to `<Head nonce={nonce}>` and `<NextScript nonce={nonce}>` in `_document.tsx`; `getServerSideProps` can read it from `req.headers["x-nonce"]` because it was set on the request.

**Key Points:**

- Generate new nonce per request (never reuse); pages must be dynamically rendered to get a per-request nonce
- Use Web Crypto (`crypto.randomUUID()` or `crypto.getRandomValues()`); `crypto.randomBytes(16)` is Node-only
- Pass nonce to all components that need inline scripts
- Load third-party scripts with the nonce (with `'strict-dynamic'`, browsers ignore host allowlists in `script-src`)
- Use `'unsafe-inline'` in development only (breaks with nonces)

**CSP Violation Reporting:**

```typescript
// Response headers - send both until report-to is universal (browsers that support report-to ignore report-uri)
"Reporting-Endpoints: csp-endpoint=\"https://your-domain.com/api/csp-report\"";
"Content-Security-Policy: ...; report-to csp-endpoint; report-uri https://your-domain.com/api/csp-report";

// Log violations - reports are not application/json, so tell the body parser which types to accept
app.post(
  "/api/csp-report",
  express.json({
    type: ["application/csp-report", "application/reports+json"],
  }),
  (req, res) => {
    console.log("CSP Violation:", JSON.stringify(req.body)); // attacker-controlled data: log it, never render it
    res.status(204).end();
  },
);
```

Test with `Content-Security-Policy-Report-Only` first, then switch to enforcing mode after fixing violations.

## 6. CSRF Protection

### Understanding CSRF Attacks

Cross-Site Request Forgery (CSRF) exploits the browser's automatic inclusion of cookies with every request. If your application uses cookie-based authentication and a user visits a malicious website while logged in, the attacker's site can trigger authenticated requests without the user's knowledge.

**Example attack scenario:**

```html
<!-- Attacker's website -->
<form action="https://bank.example.com/transfer" method="POST">
  <input name="to" value="attacker" />
  <input name="amount" value="1000" />
</form>
<script>
  document.forms[0].submit();
</script>
```

If the user is logged into bank.example.com, the browser automatically includes the authentication cookie with the request, executing the transfer.

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
- `Lax`: Cookie sent on cross-site top-level navigations that use a safe method (link clicks, GET forms); not sent on cross-site POST forms, fetch/XHR or embedded resources. Set it explicitly - Chrome's Lax-by-default still allows cross-site POST for 2 minutes after the cookie is set

**Recommendation:** Set `SameSite=Lax` (or `Strict`, as in §4) and verify the `Origin` header (or `Sec-Fetch-Site`) on every state-changing request. SameSite is scoped to the _site_, not the origin: any subdomain of your registrable domain (user content, a taken-over dangling CNAME) sends same-site requests that carry the cookie. Unless you control every host under your domain and no GET changes state, add CSRF tokens too, and always for financial transactions and account changes.

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
    cooldown:
      default-days: 7 # skip releases younger than a week
```

Dependabot's continuous monitoring means you don't need to remember to check for updates manually. Configure it to check weekly for most projects, or daily for security-critical applications. The `open-pull-requests-limit` prevents overwhelming your team with too many simultaneous PRs. `cooldown` holds version-update PRs until a release has aged (Dependabot defaults to 3 days; 7 is safer); security updates are never delayed.

**Best practice:** Turn on Dependabot alerts and security updates in the repository settings. `dependabot.yml` does not turn them on, and its `schedule` and `open-pull-requests-limit` do not apply to security updates. Do not auto-merge fresh releases, even patches: the September 2025 chalk/debug compromise shipped as patch releases (`debug@4.4.2`, `chalk@5.6.1`). Keep the `cooldown` and review major versions by hand.

### Avoiding Malicious Packages

Beyond vulnerable packages, the npm ecosystem contains malicious packages designed to steal credentials or inject backdoors. Typosquatting attacks use package names with small typos (e.g., `reacct` instead of `react`) hoping developers will install them by mistake.

**Typosquatting defense:**

```bash
# Check package before installing
npm view package-name

# Check who publishes it and when each version was released
npm view package-name maintainers time

# Verify registry signatures and provenance attestations of installed packages
npm audit signatures

# Use package-lock.json (commit to git)
npm ci  # In CI/CD (uses lock file)
```

**Before installing any package, check:**

1. **Download count** - Legitimate packages typically have >100k weekly downloads
2. **Last updated date** - Recently maintained packages indicate active development
3. **Publisher reputation** - Verified publishers or official organizations are safer
4. **GitHub stars/issues** - Active community engagement suggests trustworthiness
5. **Source code** - For critical dependencies, review the actual code

**Lock file + `npm ci` prevents:**

- Silent drift to a new (possibly malicious) version between your machine and CI
- Tarball substitution (every entry carries an `integrity` hash)

It does not stop a malicious release that enters when someone runs `npm install <pkg>` or `npm update`, or merges a Dependabot PR (the lock then records the bad version with a valid hash), and it does not stop install scripts.

The `package-lock.json` file locks your dependencies to specific versions and checksums. Use `npm ci` in CI/CD environments instead of `npm install` to ensure the exact versions from the lock file are installed, preventing attackers from injecting malicious updates between development and production.

**Supply chain attack patterns to watch for:**

Recent attacks demonstrate how npm supply chain compromises occur:

- **Ownership transfer attacks**: Popular unmaintained packages handed to a new "maintainer" who adds a malicious dependency in a patch release (e.g., event-stream 2018: `event-stream@3.3.6` pulled in `flatmap-stream@0.1.1`, which stole Bitcoin wallet keys from the Copay app)
- **Account compromise**: Maintainer accounts hijacked (phishing, reused passwords, leaked tokens), malicious versions published (e.g., ua-parser-js 2021 - ~8M downloads/week, cryptominer plus credential stealer; chalk/debug September 2025 - phished maintainer, 18 packages with 2B+ downloads/week shipped a browser crypto-wallet hijacker; axios March 2026 - `1.14.1`/`0.30.4` pulled in a remote-access trojan)
- **Self-replicating worms**: Shai-Hulud (September 2025, larger second wave in November) stole npm, GitHub and cloud tokens during install and republished itself into 500+ packages
- **Dependency confusion**: Attackers publish malicious packages with same name as internal private packages, npm installs public version (e.g., targeting tech companies' internal tools)

**Post-install script risks:**

```bash
# Check if package runs code during install
npm view package-name scripts

# npm 11 and earlier: disable auto-execution (run manually after audit)
npm install --ignore-scripts

# npm 12+: dependency scripts are blocked by default; approve per package
npm install-scripts approve esbuild  # the package whose script you reviewed
npm rebuild esbuild
```

Many packages run arbitrary code during `npm install` via post-install scripts. A malicious package can steal environment variables (often containing CI/CD secrets), modify other packages in node_modules, or establish persistence. Review scripts before allowing execution, especially for new dependencies. On npm 11 and earlier, make it the default with `ignore-scripts=true` in `.npmrc` (example below).

**Advanced protection:**

- Use tools like Socket Security that analyze package behavior (network requests, file system access, shell commands)
- Enable GitHub Dependabot security alerts for automatic vulnerability notifications
- For security-critical projects, vendor key dependencies (copy source into your repo) to isolate from supply chain

### 2025 npm Supply-Chain Attacks and What Changed

September 2025 rewrote the threat model. On September 8 a phishing mail from `npmjs.help` took over maintainer `qix`'s account and pushed a browser crypto-clipper into 18 packages (`chalk`, `debug`, `ansi-styles`, ...) with 2B+ combined weekly downloads. Days later the self-replicating **Shai-Hulud** worm used stolen npm tokens and post-install scripts to infect 500+ packages and harvest every secret it could reach. `npm audit` saw none of it.

What changed and what to do:

- **Publishing**: npm revoked all classic tokens (December 2025) and capped write tokens at 90 days. Publish your own packages with [trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC, no tokens, provenance by default).
- **Verify installs**: run `npm audit signatures` in CI next to `npm audit`.
- **Wait before upgrading**: the poisoned versions were pulled within hours. Gate on release age: npm `min-release-age`, pnpm `minimumReleaseAge` (1 day by default since pnpm 11), Dependabot `cooldown`.
- **Kill install scripts**: npm 12 blocks dependency install scripts by default; on older npm use `npm ci --ignore-scripts`.

```ini
# .npmrc (npm 11.10+) - don't be the first to install a fresh release
min-release-age=7
ignore-scripts=true
```

### SAST with Semgrep or Opengrep

Static Application Security Testing (SAST) analyzes your source code for security vulnerabilities without executing it. Unlike dependency scanning which only checks for known vulnerable packages, SAST examines your actual code patterns to find security flaws like XSS, hardcoded secrets, and injection vulnerabilities.

**Semgrep vs Opengrep vs Aikido:**

- **[Semgrep Community Edition](https://semgrep.dev/)** (Free, LGPL-2.1): Single-file analysis, community rules, more false positives
- **Semgrep AppSec Platform** (Free up to 10 contributors, then paid): Cross-file dataflow analysis, Pro rules and AI-assisted triage for cleaner signal
- **[Opengrep](https://github.com/opengrep/opengrep)** (Free, LGPL-2.1): Fork of Semgrep CE launched in January 2025 by Aikido Security with Endor Labs, Orca and other AppSec vendors; runs Semgrep-format rules, but has no hosted rule registry
- **[Aikido Security](https://www.aikido.dev/)** (Free for 2 users / 10 repos; paid plans from $300/month): hosted platform that runs SAST (Aikido's own engine plus Opengrep) alongside secrets, dependency (SCA), IaC and container scanning, with AI triage of false positives; integrates as a GitHub/GitLab app, so there is no workflow YAML to maintain. The free tier gates PRs on dependency findings only; blocking on SAST findings needs a paid plan

**Recommendation:** Use the Semgrep AppSec Platform if budget allows (cleaner signal). Cost-conscious teams should start with Semgrep CE, Opengrep or Aikido's free tier (SAST plus dependency, secret and IaC scanning in one place). Pay for Semgrep or Aikido when triage noise costs more than the licence.

**Installation:**

```bash
# Semgrep
pip install semgrep

# Opengrep (Semgrep-compatible rules; ships as a binary, not a pip package)
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash -s -- -v v1.30.0
```

**Run security scans:**

```bash
# Scan with rules from Semgrep's registry
semgrep --config=auto src/
# Opengrep has no hosted registry: point it at a pinned checkout of opengrep/opengrep-rules
# opengrep scan -f ./rules src/

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
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      # Option 1: Semgrep CE (free); semgrep-action is deprecated, run the CLI
      # Semgrep AppSec Platform: replace with `semgrep ci` and set SEMGREP_APP_TOKEN
      - run: semgrep scan --config p/security-audit --config p/react --config p/javascript --error

      # Option 2: Opengrep (free fork, standalone binary): drop `container:`, then
      # - run: curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash -s -- -v v1.30.0
      # - run: ~/.opengrep/cli/latest/opengrep scan -f ./rules src/ # ./rules = pinned checkout of opengrep/opengrep-rules
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

TruffleHog scans git repositories for accidentally committed secrets (API keys, credentials, tokens). Unlike SAST which finds code patterns, TruffleHog specifically looks for high-entropy strings and known secret formats. It detects 800+ secret types (and verifies many against the issuing API) including AWS keys, database credentials, and private keys.

**Pre-commit Hook:**

```bash
# Install TruffleHog v3 (Go binary - `pip install trufflehog` is the abandoned 2021 v2)
brew install trufflehog
# or: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin v3.97.6
```

`.git/hooks/pre-commit` (scans only the commit being made):

```bash
#!/bin/bash
trufflehog git file://. --since-commit HEAD --results=verified,unknown --fail --trust-local-git-config
```

Installing TruffleHog as a pre-commit hook blocks secrets from ever entering your repository. The hook runs before each commit and rejects the commit if secrets are detected, forcing developers to remove them before code is versioned.

**Scan entire git history:**

```bash
# Scan the full git history for secrets
trufflehog git file://. --results=verified,unknown --fail

# Scan specific files
trufflehog filesystem src/ --results=verified,unknown --fail
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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      - name: TruffleHog
        uses: trufflesecurity/trufflehog@64d939a56362f519781c53ea09b27f8d1dc0140a # v3.97.6
        with:
          version: 3.97.6 # the scanner image defaults to "latest"; pin it too
          extra_args: --results=verified,unknown
```

Run TruffleHog in CI/CD to catch secrets that bypassed pre-commit hooks (e.g., commits made with `--no-verify`) or were committed before TruffleHog was installed. The `fetch-depth: 0` gives the action the history it needs to scan every commit in the push or pull request. Actions are pinned to full commit SHAs because tags can be moved: attackers repointed the tags of `tj-actions/changed-files` (2025) and `trivy-action` (2026) to credential-stealing code. Let Dependabot bump the SHAs.

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

**Create React App (deprecated; legacy apps only):**

```bash
REACT_APP_API_URL=https://api.example.com
```

```jsx
const apiUrl = process.env.REACT_APP_API_URL;
```

Environment variables without the framework-specific prefix (`VITE_`, `REACT_APP_`, `NEXT_PUBLIC_`) are NOT included in frontend builds. The build does not fail or warn - the reference is simply replaced with `undefined` (Vite docs: `import.meta.env.DB_PASSWORD // undefined`), so the secret is not exposed but you only find out at runtime. Keep secrets out of `.env` files the frontend build reads at all.

**Important:** Even though `.env` files aren't committed to git (add them to `.gitignore`), the variables they contain are still embedded in your production JavaScript bundle. The `.env` file protects secrets during development, but doesn't prevent them from appearing in built code if they use the public prefix.

### Backend-for-Frontend Pattern

Never call third-party APIs directly from your frontend with secret keys. Instead, create backend endpoints that accept requests from your authenticated frontend, validate them, and then call third-party services using server-side secrets.

**Bad: Exposes secret API key**

```jsx
// WRONG - Secret key exposed to all users
import Stripe from "stripe";
const stripe = new Stripe("sk_live_SECRET_KEY_HERE"); // server SDK in the bundle
await stripe.paymentIntents.create({ amount: 1000, currency: "usd" });
```

**Good: Proxy through your backend**

```jsx
// Frontend - tells the backend WHAT to buy, never the price
async function createPayment(priceId) {
  return fetch("/api/payments/intent", {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" }, // without this express.json() ignores the body
    body: JSON.stringify({ priceId }),
  });
}

// Backend API route - holds the secret and derives the amount server-side (Payment Intents; the Charges API is deprecated)
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.post("/api/payments/intent", authenticateUser, async (req, res) => {
  const price = await stripe.prices.retrieve(req.body.priceId); // never trust a client-sent amount
  const intent = await stripe.paymentIntents.create({
    amount: price.unit_amount,
    currency: price.currency,
    customer: req.user.stripeCustomerId,
  });
  res.json({ clientSecret: intent.client_secret }); // return only what the browser needs
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

For Vite, legacy Create React App apps, or other frameworks without built-in header configuration, set headers in your reverse proxy or web server.

**nginx.conf:**

```nginx
# Prevent clickjacking
add_header X-Frame-Options "DENY" always;

# Prevent MIME sniffing
add_header X-Content-Type-Options "nosniff" always;

# Disable the legacy XSS auditor (OWASP: set 0; "1; mode=block" introduced XS-leaks) - rely on CSP
add_header X-XSS-Protection "0" always;

# Enforce HTTPS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Control referrer
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions policy
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

The `always` parameter ensures headers are sent even for error responses (4xx, 5xx), which is important because error pages can also be vulnerable to attacks.

**Cloudflare (Transform Rules):**

Cloudflare can add headers with a Response Header Transform Rule (dashboard: Rules → Overview → Create rule → Response Header Transform Rule).

For applications behind Cloudflare or other CDNs, you can set headers at the CDN level: the CDN adds them to every response it serves, so they apply even if the origin forgets them. They do not cover traffic that reaches the origin directly, so lock the origin to CDN traffic.

### Headers Explained

**X-Frame-Options: DENY**

Prevents your site from being embedded in iframes, protecting against clickjacking attacks. Clickjacking tricks users into clicking malicious elements by overlaying transparent iframes over legitimate content. `DENY` blocks all iframe embedding; use `SAMEORIGIN` if you need to embed your own pages in iframes.

**X-Content-Type-Options: nosniff**

Prevents browsers from MIME-sniffing responses, forcing them to respect the declared `Content-Type` header. Without this, browsers might interpret a JavaScript file as HTML or vice versa based on content analysis, enabling certain XSS attacks where attackers upload malicious files with incorrect extensions.

**Strict-Transport-Security (HSTS)**

Forces browsers to always use HTTPS for all future requests to your domain for one year (`max-age=31536000` seconds). This prevents SSL-stripping attacks where attackers downgrade connections from HTTPS to unencrypted HTTP. The `includeSubDomains` directive applies this to all subdomains as well. Once a browser has seen the header over HTTPS, it refuses to connect via HTTP even if the user types `http://`. The first visit (and any visit after `max-age` expires) is still exposed; add `preload` and submit the domain to hstspreload.org once every subdomain serves HTTPS.

**Referrer-Policy: strict-origin-when-cross-origin**

Controls what referrer information browsers send with requests. `strict-origin-when-cross-origin` sends only the origin (domain) for cross-origin requests while sending the full URL for same-origin requests. This balances privacy (external sites don't see your full URLs) with analytics needs (your own analytics can track full paths). More restrictive policies like `no-referrer` provide better privacy but break some analytics and security features.

**Permissions-Policy: geolocation=(), microphone=(), camera=()**

Disables browser features your application doesn't use. Even if malicious injected scripts try to access the camera, microphone, or location, the browser will block these requests at the API level. This implements the principle of least privilege - only enable features your application actually needs. For applications that do need these features, specify allowed origins: `camera=(self), microphone=(self)`.

**Subresource Integrity (not a header, same job)**

Any `<script>` or `<link>` you load from a third-party CDN runs with full access to your page. After the polyfill.io domain changed hands in February 2024, it started injecting malware (disclosed June 2024) into the 100k+ sites that embedded it. SRI pins the exact bytes: the browser refuses to run a resource whose hash doesn't match. Prefer bundling third-party code with Vite so nothing loads from a CDN at all; when you must, add `integrity` and `crossorigin`, and remember SRI only works for immutable, versioned URLs.

```html
<script
  src="https://cdn.example.com/lib@1.2.3/lib.min.js"
  integrity="sha384-<base64 hash of the exact file>"
  crossorigin="anonymous"
></script>
```

**Testing your configuration:**

Visit securityheaders.com with your production URL to verify all headers are properly set and receive a security grade. This free tool checks for missing or misconfigured headers and explains their security implications.

## 10. React-Specific Security Pitfalls

Beyond React's automatic protections and the configuration discussed in previous sections, several React-specific patterns and development practices require careful security consideration. These pitfalls often arise from convenience features or development tools that can introduce vulnerabilities if not properly managed in production.

### Dangerous Props

React 18 does not validate URL protocols in props like `href`, `src`, or `formAction`. React 19 blocks only `javascript:` URLs there. Neither version checks other schemes or where the URL points, so validate user-provided URLs yourself.

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

Malicious URLs can use `javascript:alert('xss')` protocol to execute code when clicked, or `data:text/html,...` in an `<iframe src>` to render attacker HTML (browsers block `data:` as a top-level navigation, so it does nothing in a link). Always validate that user-provided URLs start with safe protocols before rendering them. For internal navigation, use React Router's `<Link>` with paths you build, never raw user input: `<Link>` renders any absolute URL, `javascript:` included, straight into `href`.

`rel="noopener noreferrer"` matters for links that open a new tab (`target="_blank"`): it stops the new page from using `window.opener` to redirect yours (tab-nabbing) and strips the `Referer` header. Modern browsers already imply `noopener` for `target="_blank"`; keep it for older ones.

### Third-Party Components

Third-party React components introduce code you don't control into your application. A malicious or compromised component library can steal user data, inject tracking scripts, or create backdoors.

**Audit before using:**

```bash
# Check downloads and github stars
npm view react-some-package

# Check for known vulnerabilities
npm audit
```

Apply the same five checks as [Avoiding Malicious Packages](#avoiding-malicious-packages): weekly downloads, recent commits, publisher reputation, `npm audit` after install, and a read of the source for anything security-critical. Popularity shows a package is established, not that each release was reviewed: `debug` and `chalk` (billions of weekly downloads) shipped browser malware in September 2025.

Popular, well-maintained component libraries (MUI, Ant Design, Chakra UI, Radix UI) have security teams and established vulnerability disclosure processes. Newer or niche libraries may not have undergone security review. Be especially cautious with components that handle sensitive data (payment forms, authentication UI, file uploads).

### React DevTools in Production

React DevTools and debug code can expose application internals, component state, and sensitive user data. Development builds include extensive debugging information in the browser's React DevTools extension, allowing inspection of component props, state, and hooks.

**Production builds do not hide state:** they strip development-only warnings and checks, but the React DevTools extension still attaches to production React and shows component props, state and hooks (with minified names). Treat everything you send to the browser as readable by the user; keep data they must not see on the server.

Modern build tools (Vite, Next.js, legacy Create React App) automatically exclude development-specific code in production builds through the `NODE_ENV=production` environment variable. Verify it by loading the site with the React DevTools extension installed: its icon must report the production build of React. Do not grep the bundle for `__REACT_DEVTOOLS_GLOBAL_HOOK__` - production `react-dom` contains that string too (it is how the renderer registers with the extension). If you want a bundle check, search for a development-only string such as `not wrapped in act` - it must not appear.

Additionally, remove or guard all `console.log` statements that might leak sensitive information. Use environment checks to conditionally enable debugging:

```jsx
if (import.meta.env.DEV) {
  console.log("Debug info:", userData);
}
```

### Source Maps

Source maps allow developers to debug minified production code by mapping it back to the original source. However, they also expose your original source code, comments and business logic to anyone who can access them. They reveal no secret the minified bundle does not already ship (see §8).

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

For most applications, hidden source maps with error tracking service integration provide the best balance. `'hidden'` only drops the `//# sourceMappingURL` comment: the `.map` files are still written to `dist/` next to each bundle, so anyone can fetch `app.js.map` unless you delete them after upload (Sentry's Vite plugin: `sourcemaps.filesToDeleteAfterUpload`) or deny `*.map` at the web server.

If you need source maps for error tracking:

```javascript
// Upload to error tracking service (Sentry, etc)
// Serve source maps only to authenticated error tracking service
sourcemap: "hidden"; // Generates maps but doesn't link in JS
```

Error tracking services like Sentry can automatically upload your source maps during deployment and use them to de-minify error stack traces. The maps are stored on Sentry's servers with authentication required; delete the local copies after upload so they never reach end users.

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

- [React: dangerouslySetInnerHTML](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [React Server Components advisory (CVE-2025-55182)](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [TypeScript](https://www.typescriptlang.org/)
- [CVE-2025-29927: Next.js middleware authorization bypass](https://github.com/advisories/GHSA-f82v-jwr5-mffw)
- [Vercel postmortem on Next.js middleware bypass](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass)
- [Next.js proxy.ts (formerly middleware.ts)](https://nextjs.org/docs/app/api-reference/file-conventions/proxy)
- [Next.js Content Security Policy guide](https://nextjs.org/docs/app/guides/content-security-policy)

### Security Tools

- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Semgrep](https://semgrep.dev/)
- [Opengrep](https://github.com/opengrep/opengrep)
- [Aikido Security](https://www.aikido.dev/)
- [Dependabot](https://github.com/dependabot)
- [npm audit](https://docs.npmjs.com/cli/commands/npm-audit)
- [DOMPurify](https://github.com/cure53/DOMPurify)
- [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers)
- [pnpm minimumReleaseAge](https://pnpm.io/settings/dependency-resolution#minimumreleaseage)
- [Dependabot cooldown](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference)
- [GitHub Actions: pin actions to a full-length commit SHA](https://docs.github.com/en/actions/reference/security/secure-use)

### Web Security Standards

- [OWASP Top 10](https://owasp.org/projects/top-ten)
- [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
- [SameSite Cookies](https://web.dev/articles/samesite-cookies-explained)
- [OWASP Frontend Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- [Subresource Integrity (SRI)](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity)
- [RFC 9700: OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html)

### Incidents

- [GitHub: Our plan for a more secure npm supply chain (Shai-Hulud)](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)
- [Aikido: npm debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [CISA: Supply chain compromise impacts axios (2026)](https://www.cisa.gov/news-events/alerts/2026/04/20/supply-chain-compromise-impacts-axios-node-package-manager)
- [Rapid7: npm library ua-parser-js hijacked](https://www.rapid7.com/blog/post/2021/10/25/npm-library-ua-parser-js-hijacked-what-you-need-to-know/)
- [Snyk: Post-mortem of the malicious event-stream backdoor](https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/)
- [tj-actions/changed-files tag compromise (CVE-2025-30066)](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)
- [Trivy and trivy-action tag compromise (2026)](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- [Sansec: Polyfill supply chain attack](https://sansec.io/research/polyfill-supply-chain-attack)

### Authentication

- [Auth0](https://auth0.com/)
- [Clerk](https://clerk.com/)
- [Firebase Auth](https://firebase.google.com/docs/auth)
- [AWS Cognito](https://aws.amazon.com/cognito/)

### Security Testing

- [SecurityHeaders.com](https://securityheaders.com/)
- [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory)
