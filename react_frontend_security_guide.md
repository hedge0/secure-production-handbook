# React Frontend Security Guide

**Last Updated:** January 27, 2026

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
   - [What is CSRF?](#what-is-csrf)
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
    - [dangerouslySetInnerHTML](#dangerouslysetinnerhtml)
    - [User-Controlled URLs](#user-controlled-urls)
    - [Third-Party Scripts](#third-party-scripts)
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

React provides automatic XSS protection by escaping all values rendered in JSX expressions. When you render user input like `<div>{userName}</div>`, React automatically escapes HTML special characters (`<`, `>`, `&`, `"`, `'`) before inserting them into the DOM. This means even if a user submits malicious input like `<script>alert('xss')</script>`, React renders it as harmless text: `&lt;script&gt;alert('xss')&lt;/script&gt;`.

This automatic escaping applies to both element content and JSX attributes. React sanitizes values in `href`, `src`, and other attributes, preventing most common XSS attacks. This is why React applications are inherently more secure than traditional DOM manipulation approaches where developers must remember to escape every user-controlled value.

**Key protection mechanisms:**

- All JSX expressions (`{value}`) are escaped before rendering
- Attribute values are sanitized to prevent injection
- String concatenation in JSX is safe by default
- React's reconciliation algorithm validates content before DOM updates

### When React DOESN'T Protect You

React's automatic protections have three critical gaps where developers must implement additional security measures:

**1. dangerouslySetInnerHTML**

The `dangerouslySetInnerHTML` prop bypasses React's XSS protection entirely. When you use this prop, React inserts raw HTML directly into the DOM without any escaping or validation. This is necessary for rendering rich text content (blog posts, comments with formatting, WYSIWYG editor output) but creates a direct XSS vulnerability if the HTML contains malicious scripts.

Never pass user-controlled HTML to `dangerouslySetInnerHTML` without sanitization. Use DOMPurify to remove dangerous HTML elements and attributes before rendering. DOMPurify strips `<script>` tags, event handlers (`onclick`, `onerror`), and dangerous protocols (`javascript:`), while preserving safe formatting elements like `<b>`, `<i>`, and `<p>`.

Install DOMPurify: `npm install dompurify @types/dompurify`

**When you need DOMPurify:**

- User-generated rich text (blog comments, forum posts)
- WYSIWYG editor content
- Markdown-to-HTML conversion output
- HTML from external APIs or third-party sources
- Any scenario where you use `dangerouslySetInnerHTML`

**2. javascript: URLs**

React does not validate URL protocols in `href` attributes. A malicious URL like `javascript:alert('xss')` will execute code when the user clicks the link. This is particularly dangerous in applications where users can submit links (social networks, forums, comment sections).

Always validate user-provided URLs before rendering them in `<a>` tags or `window.location` assignments. Check that URLs start with safe protocols (`http://` or `https://`) and reject anything else. For internal navigation, use React Router's `<Link>` component instead of `<a>` tags with user-controlled URLs.

**3. Server-Side Rendering (SSR) with User Data**

In Next.js or other SSR frameworks, user data rendered on the server can create XSS vulnerabilities if not handled carefully. While React's client-side escaping still applies, be cautious when interpolating user data into HTML strings or script tags during server rendering. Use React's built-in rendering methods rather than string concatenation.

## 4. Authentication & Session Management

### JWT Storage (Recommended Approach)

The most critical decision in React authentication is where to store tokens. **Never store JWTs in localStorage or sessionStorage** - both are vulnerable to XSS attacks. Any JavaScript running in your application (including third-party scripts or XSS payloads) can read localStorage/sessionStorage and steal tokens.

**Use HttpOnly cookies for authentication tokens.** HttpOnly cookies are not accessible to JavaScript, which means even if an attacker injects malicious code into your application, they cannot read the authentication token. The browser automatically includes HttpOnly cookies with every request to your API, providing secure, convenient authentication.

**Backend cookie configuration requirements:**

- `httpOnly: true` - JavaScript cannot access the cookie
- `secure: true` - Cookie only sent over HTTPS
- `sameSite: 'strict'` - Prevents CSRF attacks by blocking cross-site requests
- `maxAge: 15 * 60 * 1000` - Short expiration (15 minutes) limits damage if token is compromised

**Frontend implementation:**

- Use `credentials: 'include'` in all fetch requests to send/receive cookies
- Never try to read the token in JavaScript (it's not accessible)
- Backend validates token on each request and returns user data or 401

This approach is more secure than storing tokens in JavaScript-accessible storage, but requires your API and frontend to be on the same domain (or properly configured CORS with credentials).

**TypeScript is strongly recommended** for authentication code because type safety prevents common security bugs. Type definitions ensure you handle all response states (success, unauthorized, network error) and validate user data shape before trusting it.

### Token Refresh Pattern

Short-lived access tokens (15 minutes) combined with longer-lived refresh tokens (7 days) provide security and convenience. If an access token is stolen, it expires quickly, limiting damage. The refresh token, stored in a separate HttpOnly cookie, generates new access tokens without requiring the user to re-authenticate.

**Implementation approach:**

- Access token expires in 15 minutes
- Refresh token expires in 7 days
- Frontend automatically refreshes access token every 14 minutes (before expiration)
- If refresh fails (expired or revoked), redirect user to login

**Why this is more secure than long-lived tokens:**

- Stolen access tokens expire quickly (15-minute window)
- Refresh tokens can be revoked server-side (logout all devices)
- Failed refresh attempts can trigger security alerts
- User experience is seamless (auto-refresh in background)

**Implementation considerations:**

- Set up refresh interval slightly before token expiration (14 minutes for 15-minute tokens)
- Handle refresh failures gracefully by redirecting to login
- Clear any client-state when authentication fails
- Monitor failed refresh attempts for suspicious activity

## 5. Content Security Policy (CSP)

Content Security Policy (CSP) provides defense-in-depth protection against XSS attacks. Even if an attacker bypasses React's protections and injects malicious code into your HTML, CSP prevents that code from executing by restricting which scripts the browser will run.

**How CSP works:** The server sends a `Content-Security-Policy` header that tells the browser which sources are allowed for scripts, styles, images, and other resources. If a script tries to execute from an unauthorized source (including inline scripts), the browser blocks it and reports a violation.

**Essential directives for React applications:**

- `default-src 'self'` - Only load resources from your own domain by default
- `script-src 'self'` - Only execute JavaScript from your domain (blocks inline scripts and external scripts)
- `style-src 'self' 'unsafe-inline'` - Allow CSS from your domain and inline styles (React uses inline styles)
- `connect-src 'self' https://api.example.com` - Restrict fetch/XHR to your domain and specific API endpoints
- `img-src 'self' data: https:` - Allow images from your domain, data URIs, and HTTPS sources
- `frame-ancestors 'none'` - Prevent your site from being embedded in iframes (clickjacking protection)
- `base-uri 'self'` - Prevent `<base>` tag injection that could hijack relative URLs
- `form-action 'self'` - Restrict form submissions to your domain

**Development vs Production CSP:**

Development environments often require relaxed CSP to support hot module reloading and development tools. Next.js development mode needs `'unsafe-eval'` and `'unsafe-inline'` for script-src. Use environment detection to apply stricter CSP in production while maintaining developer experience locally.

**Third-party scripts (Google Analytics, Stripe, etc):**

Third-party scripts require CSP exceptions. Two secure approaches:

1. **Nonce-based**: Server generates unique random value per request, adds to CSP header and script tags
2. **Hash-based**: Calculate SHA-256 hash of script content, whitelist in CSP

Nonce-based is preferred because it works with dynamic scripts and provides better security.

**CSP violation reporting:**

Configure CSP to report violations to your backend so you can detect attacks or misconfigurations. Use `report-uri` or `report-to` directive pointing to an endpoint that logs violation details (blocked resource, page URL, user agent). Monitor these reports for patterns indicating attack attempts or compatibility issues.

**Implementation:**

For Vite/CRA, add CSP headers via Nginx or CloudFlare. For Next.js, configure in `next.config.js` headers section. Always test CSP in browser console to catch violations before deployment.

## 6. CSRF Protection

### Understanding CSRF Attacks

Cross-Site Request Forgery (CSRF) attacks exploit the browser's automatic inclusion of cookies with every request to a domain. If your application uses cookie-based authentication and a user visits a malicious website while logged into your application, the attacker's site can trigger authenticated requests to your API without the user's knowledge.

**Attack scenario:** User logs into `yourbank.com` (cookie stored). User visits `evil.com` which contains a hidden form that auto-submits to `yourbank.com/transfer?to=attacker&amount=1000`. Because the browser automatically includes the authentication cookie with the request, the transfer executes as the logged-in user.

**When CSRF protection is required:**

- Your API uses cookie-based authentication (HttpOnly cookies)
- Your API has state-changing endpoints (POST, PUT, DELETE)
- Your API accepts requests from browser-based clients

**When CSRF protection is NOT needed:**

- Bearer token authentication in Authorization header (tokens aren't automatically sent)
- Read-only GET requests (no state changes)
- API-only backends with no browser clients

### Defense Strategies

**Option 1: CSRF Tokens (Traditional)**

Backend generates random token, stores in session, and provides to frontend. Frontend includes token in request headers for state-changing operations. Backend validates token matches session. This prevents CSRF because malicious sites can't access the token (same-origin policy blocks cross-site JavaScript from reading your site's content).

Implementation: Use middleware like `csurf` (Express) or equivalent. Frontend fetches token on load and includes in `X-CSRF-Token` header for POST/PUT/DELETE requests.

**Option 2: SameSite Cookies (Modern, Recommended)**

Setting `SameSite=Strict` or `SameSite=Lax` on authentication cookies prevents the browser from including cookies in cross-site requests. `Strict` blocks cookies in all cross-site contexts (most secure but breaks legitimate cross-site navigation). `Lax` allows cookies in top-level GET navigations but blocks them in POST/PUT/DELETE requests (balances security and usability).

**Recommended configuration:** `SameSite=Strict` for APIs, `SameSite=Lax` for web applications with external links.

**Defense-in-depth approach:**

Combine multiple protections:

1. Set `SameSite=Strict` or `SameSite=Lax` on cookies (primary defense)
2. Verify `Origin` or `Referer` header matches your domain (backup defense)
3. Require custom headers for state-changing requests (attackers can't set custom headers cross-site)
4. Use CSRF tokens for extra-sensitive operations (financial transactions, account changes)

Most modern applications can rely primarily on SameSite cookies with Origin/Referer verification as backup.

function TransferForm() {
const csrfToken = useCSRF();

async function handleSubmit(e) {
e.preventDefault();
const formData = new FormData(e.target);

    await fetch("/api/transfer", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken, // Include token
      },
      body: JSON.stringify(Object.fromEntries(formData)),
    });

}

return (
<form onSubmit={handleSubmit}>
<input name="to" />
<input name="amount" />
<button type="submit">Transfer</button>
</form>
);
}

````

### Alternative: SameSite Cookies

**Modern browsers support SameSite:**

```javascript
// Backend sets SameSite cookie
res.cookie("token", jwt, {
  httpOnly: true,
  secure: true,
  sameSite: "strict", // or 'lax'
});
````

**SameSite=Strict:** Cookie never sent on cross-site requests (best protection, may break legitimate flows)
**SameSite=Lax:** Cookie sent on top-level navigation (GET only)

**Recommendation:** Use SameSite=Lax + CSRF tokens for state-changing requests.

## 7. Dependency Security

Vulnerable dependencies are one of the most common security issues in React applications. Third-party packages can contain known security flaws that attackers actively exploit, and malicious packages can be intentionally uploaded to npm with names similar to popular libraries (typosquatting).

### npm audit

npm audit scans your `package.json` and `package-lock.json` for known vulnerabilities in the npm registry database. Run `npm audit` regularly to identify vulnerable dependencies and `npm audit fix` to automatically update to patched versions.

**Severity levels:**

- **Critical/High**: Immediate action required - exploitable vulnerabilities that can compromise your application
- **Moderate**: Address in next release cycle - potential security issues with lower exploitability
- **Low**: Address when convenient - minor issues or unlikely attack scenarios

**CI/CD integration:** Run `npm audit --audit-level=high` in your build pipeline to fail builds with critical vulnerabilities.

**Important limitation:** npm audit only detects _known_ vulnerabilities with published CVEs. It cannot detect malicious code in packages without reported issues.

### Dependabot

Dependabot automatically creates pull requests when new versions of your dependencies are released, including security patches. Enable Dependabot in your GitHub repository settings to receive automated PRs when vulnerable dependencies are detected.

Configure in `.github/dependabot.yml` to control update frequency (daily, weekly, monthly) and auto-merge settings for minor/patch updates.

**Best practice:** Enable automatic security updates for patch/minor versions, but manually review major version updates for breaking changes.

### Avoiding Malicious Packages

Before installing any npm package:

1. **Check download count** - Legitimate packages typically have >100k weekly downloads
2. **Review recent commits** - Active maintenance indicates trustworthy maintainers
3. **Check publisher** - Verified publishers or official organizations are safer
4. **Read source code** - For critical dependencies, review the actual code
5. **Check package age** - Newly published packages with high-value names may be typosquatting attempts

**Red flags:**

- New package with name similar to popular library (e.g., `reacct` instead of `react`)
- No README, minimal documentation, or generic descriptions
- Suspicious permissions requests or postinstall scripts
- Published by unknown individual with no other packages

**Lock file protection:** Use `package-lock.json` (committed to git) and `npm ci` in CI/CD to prevent unauthorized package modifications and ensure consistent dependencies across environments.

### SAST with Semgrep or Opengrep

Static Application Security Testing (SAST) analyzes source code for security vulnerabilities without executing it. Semgrep (paid) and Opengrep (free, open-source) scan React/JavaScript code for patterns indicating security issues.

**What SAST tools catch:**

- XSS via `dangerouslySetInnerHTML` without sanitization
- Hardcoded secrets and API keys
- SQL injection vulnerabilities
- Command injection patterns
- Insecure randomness (Math.random for security contexts)
- Path traversal vulnerabilities

**Semgrep vs Opengrep:**

- **Semgrep** (paid): AI-powered analysis reduces false positives, enterprise support, priority updates
- **Opengrep** (free): Open-source fork with same CLI, community rules, more false positives

**Recommendation:** Use Semgrep if budget allows. Use Opengrep for cost-conscious teams willing to filter false positives.

Run in CI/CD pipeline to block PRs containing security vulnerabilities. Configure GitHub Actions to run scans on every pull request and fail on critical findings.

### Secret Scanning with TruffleHog

TruffleHog scans git repositories for accidentally committed secrets (API keys, credentials, tokens). It detects hundreds of secret types including AWS keys, database credentials, OAuth tokens, and private keys.

**Deployment approaches:**

- **Pre-commit hook:** Install TruffleHog as git pre-commit hook to block secrets before commit (prevents issues)
- **CI/CD scanning:** Scan entire repository history and new commits in GitHub Actions (catches bypassed hooks)

**Prevention is easier than remediation:** Once secrets are committed to git, they must be considered compromised even after removal (git history preserves deleted content). Immediately rotate any exposed credentials.

Always add `.env`, `.env.local`, `.env.*.local`, `secrets/`, `*.pem`, and `*.key` to `.gitignore` to prevent accidental commits.

## 8. Environment Variables & Secrets

**Critical principle: Frontend code is PUBLIC.** Anyone can view source, inspect network requests, and decompile your JavaScript bundles. Never store secrets in frontend code, environment variables, or configuration files.

### What NOT to Put in Frontend

**Never include in frontend:**

- Database credentials or connection strings
- API secret keys (keys starting with `sk_`, `secret_`, or similar prefixes)
- Private encryption keys
- OAuth client secrets
- Internal URLs or infrastructure details
- Any credential that provides write access or administrative privileges

**Safe for frontend:**

- API URLs (if publicly documented)
- Public keys (Stripe publishable keys starting with `pk_`, Google Maps API keys)
- Analytics IDs (Google Analytics, Segment)
- Feature flags
- Environment identifiers (development vs production)

### Backend-for-Frontend Pattern

Never call third-party APIs directly from frontend with your secret keys. Instead, proxy requests through your backend API which holds the secrets server-side. This pattern applies to payment processing (Stripe, PayPal), email services (SendGrid, Mailgun), SMS (Twilio), and any API requiring authentication.

**Implementation:**

- Frontend calls your backend endpoint (`/api/payments/charge`)
- Backend authenticates the user's request
- Backend calls third-party API using server-side secret
- Backend validates and sanitizes response before returning to frontend

This approach ensures secrets never leave your server, allows request validation and rate limiting, and provides audit logging for sensitive operations.

### Environment Variable Naming

**Vite:** Prefix with `VITE_` (e.g., `VITE_API_URL`), accessed via `import.meta.env.VITE_API_URL`  
**Create React App:** Prefix with `REACT_APP_` (e.g., `REACT_APP_API_URL`), accessed via `process.env.REACT_APP_API_URL`  
**Next.js:** Prefix with `NEXT_PUBLIC_` (e.g., `NEXT_PUBLIC_API_URL`), accessed via `process.env.NEXT_PUBLIC_API_URL`

Always add `.env`, `.env.local`, and `.env.*.local` to `.gitignore` to prevent accidental commits.

## 9. Browser Security Headers

Security headers configure browser behavior to provide defense-in-depth protection against attacks. These headers work independently of your application code, so even if vulnerabilities exist in your React application, properly configured headers can mitigate the impact.

### Essential Security Headers

**X-Frame-Options: DENY**  
Prevents your site from being embedded in iframes, protecting against clickjacking attacks where attackers overlay invisible iframes to trick users into clicking malicious content while thinking they're interacting with your site.

**X-Content-Type-Options: nosniff**  
Prevents browsers from MIME-sniffing responses, forcing them to respect declared Content-Type headers. Without this header, browsers might interpret JavaScript files as HTML or vice versa, enabling certain XSS attacks.

**Strict-Transport-Security (HSTS): max-age=31536000; includeSubDomains**  
Forces browsers to always use HTTPS for future requests to your domain for one year (31536000 seconds). Protects against SSL-stripping attacks where attackers downgrade connections to unencrypted HTTP.

**Referrer-Policy: strict-origin-when-cross-origin**  
Controls what referrer information browsers send with requests. This setting sends only the origin (domain) for cross-origin requests while sending the full URL for same-origin requests, balancing privacy and analytics needs.

**Permissions-Policy: geolocation=(), microphone=(), camera=()**  
Disables unnecessary browser features that your application doesn't use. Prevents malicious injected scripts from accessing user's camera, microphone, or location even if other protections fail.

### Configuration

**Next.js:** Configure headers in `next.config.js` via async headers() function  
**Vite/CRA:** Configure via Nginx, CloudFlare Transform Rules, or reverse proxy  
**CloudFlare:** Add headers via Transform Rules in dashboard (Settings → Transform Rules → Modify Response Header)

Test your configuration at securityheaders.com to verify all headers are properly set and receive security grade.

## 10. React-Specific Security Pitfalls

Beyond React's automatic protections, several React-specific patterns require careful security consideration.

### User-Controlled URLs in Props

Never pass user-controlled values directly to `href`, `src`, or other URL-accepting props without validation. Malicious URLs can use `javascript:` protocol to execute code when clicked, or `data:` URIs to inject content. Always validate that user-provided URLs start with safe protocols (`http://` or `https://`) before rendering them in links or redirects.

For internal navigation, use React Router's `<Link>` component instead of `<a>` tags with user-controlled values. React Router's navigation is inherently safer since it doesn't support `javascript:` protocol.

### Third-Party React Components

Third-party components introduce code you don't control into your application. Before adding any React component library:

- Check weekly download counts (prefer >100k/week indicating active use)
- Review recent commits and issue responses (active maintenance suggests security consciousness)
- Verify publisher reputation (official organizations or verified individuals)
- Check for known vulnerabilities with `npm audit`
- Read the actual source code for security-critical components

Popular, well-maintained component libraries (Material-UI, Ant Design, Chakra UI) have security teams and vulnerability disclosure processes. Newer or niche libraries may not have undergone security review.

### Source Maps in Production

Source maps make debugging easier by mapping minified production code back to original source, but they expose your application's structure, variable names, and business logic to anyone who can view them. Attackers can use source maps to understand your application's architecture and identify security vulnerabilities.

**Options:**

1. **No source maps** (`sourcemap: false`): Most secure, but makes production debugging difficult
2. **Hidden source maps** (`sourcemap: 'hidden'`): Generates maps but doesn't reference them in JavaScript files - upload to error tracking services (Sentry, Rollbar) that serve them only to authenticated services
3. **Inline source maps**: Never use in production - exposes everything

For most applications, hidden source maps with error tracking service integration provide the best balance of security and debuggability.

### Development Tools in Production

React DevTools, console.logs, and debug assertions should never appear in production builds. Modern build tools (Vite, Next.js, Create React App) automatically remove development code in production builds, but verify by checking for `__REACT_DEVTOOLS_GLOBAL_HOOK__` in your production JavaScript bundle.

Remove or guard all console.log statements that might leak sensitive information (user data, API responses, authentication states). Use environment checks (`if (import.meta.env.DEV)`) to conditionally enable debugging code only in development.

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
- [TypeScript](https://www.typescriptlang.org/) - Type safety for production apps

### Security Tools

- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secret scanning
- [Semgrep](https://semgrep.dev/) - SAST (AI-powered, paid)
- [Opengrep](https://github.com/opengrep/opengrep) - SAST (open-source, free)
- [Dependabot](https://github.com/dependabot) - Automated dependency updates
- [npm audit](https://docs.npmjs.com/cli/v9/commands/npm-audit) - Dependency scanner
- [DOMPurify](https://github.com/cure53/DOMPurify) - HTML sanitization

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

- [SecurityHeaders.com](https://securityheaders.com/) - Test your headers
- [Mozilla Observatory](https://observatory.mozilla.org/) - Security scan
