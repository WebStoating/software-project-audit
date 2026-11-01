# OWASP Top 10:2025 coverage

Source: https://owasp.org/Top10/2025/ (redirects to https://top10.owasp.org/2025). Retrieved 2026-10-27. Every item needs a coverage outcome in the audit (`verified_pass`, `verified_fail`, `reviewed_no_issue`, `needs_verification`, `not_reviewed`, `not_applicable`). Scanner hits are leads; a failed or skipped scanner is never a clean result. Check IDs refer to `methodology.md`.

### A01:2025 Broken Access Control

**Python:** Django views/DRF viewsets without `permission_classes` or object-level checks (`Model.objects.get(pk=pk)` without owner filter); Flask routes lacking `@login_required`; FastAPI routes without `Depends(auth)`; SQLAlchemy queries not scoped by tenant; CORS `allow_origins=['*']` with credentials; SSRF and CSRF sit here too.

**JS/TS/Node/frontend:** Express routes with no auth middleware; `findById(req.params.id)` without owner check (IDOR); Next.js route handlers/server actions that trust client-sent user IDs or role; admin checks only in React/Vue UI; middleware matcher gaps; `cors({origin:true, credentials:true})`.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/cwe-top-25`, `p/python`, `p/javascript`, `p/typescript` (csrf-exempt, open-redirect, CORS misconfiguration and framework access-control rules); Bandit B501 (verify off) is adjacent only. No scanner proves missing authorization: every hit is a lead. A scanner hit is a lead, not a finding.

**Manual checks:** Enumerate every route/handler and confirm authentication plus per-object authorization; test horizontal (other user's ID) and vertical (role) access by reading code paths; check tenant scoping, CSRF protection on cookie sessions, CORS, open redirects, and forced browsing to admin or internal endpoints; check server-fetched URLs (SSRF).

**Rolls up to:** SEC-02, SEC-06, SEC-11, SEC-12, SEC-05, SEC-13, ARC-06, ARC-12, DATA-05

### A02:2025 Security Misconfiguration

**Python:** Django `DEBUG=True`, `ALLOWED_HOSTS=['*']`, missing `SECURE_*`/cookie flags, default `SECRET_KEY`; Flask `app.run(debug=True)` (Bandit B201); FastAPI docs/openapi exposed in prod; verbose tracebacks; default credentials; permissive CORS; unneeded services in containers.

**JS/TS/Node/frontend:** Express without `helmet`, `x-powered-by` on, stack traces returned by default error handler; Next.js source maps/`NEXT_PUBLIC_*` leaks and missing security headers; CSP absent or `unsafe-inline`; dev servers or debug flags in production config.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/python` (Django/Flask debug and settings rules), `p/javascript`; Bandit B201, B104, B108; Checkov and Trivy misconfiguration checks (IaC, compose, Dockerfile, K8s: public buckets, open security groups, no encryption, root containers); Hadolint (root user, latest tags); actionlint/zizmor for workflow permissions. A scanner hit is a lead, not a finding.

**Manual checks:** Review production settings per environment: debug off, error responses generic, security headers, cookie flags, TLS, default accounts, exposed admin/docs/metrics endpoints, container user and ports, IaC network exposure, cloud storage ACLs; compare dev vs prod config.

**Rolls up to:** SEC-18, SEC-05, INFRA-03, INFRA-12, INFRA-13, INFRA-02, CICD-11, CICD-12, CICD-09

### A03:2025 Software Supply Chain Failures

**Python:** Unpinned or unlocked `requirements.txt`/Pipfile/poetry without lock; packages with known CVEs; typosquats or private-name collisions; `pip install` from URLs; `--extra-index-url`; build scripts executing remote code; unverified base images.

**JS/TS/Node/frontend:** Missing or ignored `package-lock.json`/`pnpm-lock.yaml`; `postinstall` scripts; `npm install` instead of `npm ci`; scoped packages without registry config; unpinned GitHub Actions (`@main`); CDN `<script>` without SRI; abandoned or vulnerable packages.

**Scanner leads:** OSV-Scanner and Trivy on all manifests and lockfiles (advisory leads, reachability not proven; a shared advisory is one lead); zizmor and actionlint for unpinned actions and injection; Hadolint DL3006/DL3007 (untagged or latest bases); Checkov for CI/IaC; Gitleaks for leaked registry tokens; lockfile, install-script and registry checks are manual. A scanner hit is a lead, not a finding.

**Manual checks:** Inventory manifests and lockfiles; triage OSV results by reachability and exposure; check pinning, integrity hashes, update automation, CI action pinning by SHA, provenance of build artifacts, dependency-confusion controls, and whether tested artifact equals deployed artifact.

**Rolls up to:** DEP-01, DEP-02, DEP-03, DEP-04, DEP-05, DEP-08, DEP-09, DEP-10, DEP-12, CICD-01, CICD-05, CICD-09, CICD-10

### A04:2025 Cryptographic Failures

**Python:** `hashlib.md5/sha1` for passwords or tokens (Bandit B324), `random` instead of `secrets` (B311), hardcoded keys/IVs, `verify=False` (B501), `ssl._create_unverified_context`, plain-text or reversible password storage, `DES`/`ECB`, JWT `algorithms=['none']` or unverified decode, PII stored unencrypted.

**JS/TS/Node/frontend:** `Math.random()` for tokens, `crypto.createHash('md5')`, `jwt.verify` missing algorithm pin or `jwt.decode` used as verify, secrets in `localStorage`, `rejectUnauthorized:false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, client-side crypto of secrets, HTTP URLs for APIs.

**Scanner leads:** Bandit B303, B304, B305, B324, B311, B501, B502-B505; Semgrep `p/cwe-top-25`, `p/python`, `p/javascript` (JWT and weak-crypto rules); Gitleaks (redacted) for key material; Checkov for unencrypted storage/transit in IaC. A scanner hit is a lead, not a finding.

**Manual checks:** Confirm password hashing uses bcrypt/argon2/scrypt with per-user salt; keys loaded from a secret store, not source; TLS enforced and certificates verified; JWT algorithm and expiry validated; sensitive data encrypted at rest where required; cookie `Secure` flags; key rotation exists.

**Rolls up to:** SEC-05, SEC-04, SEC-01, SEC-08, SEC-15, SEC-16, INFRA-04, INFRA-11

### A05:2025 Injection

**Python:** SQL via f-strings/`%`/`.format` in `cursor.execute`, `.raw()`, `.extra()`, SQLAlchemy `text()` with interpolation (Bandit B608); `os.system`/`subprocess(shell=True)` (B602, B605); `eval`/`exec` (B307, B102); Jinja `|safe`/`mark_safe` (B703, B701) XSS; LDAP/XPath/template injection; header and log injection.

**JS/TS/Node/frontend:** SQL via template strings in `pg`/`mysql`/Sequelize `query`; NoSQL operator injection (`find(req.body)`); `child_process.exec` with input; `eval`/`new Function`; React `dangerouslySetInnerHTML`, Vue `v-html`, `innerHTML`, `document.write`; Next.js unsanitized `href` (`javascript:`); prototype pollution.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/cwe-top-25`, `p/python`, `r/python.lang.security.audit`, `p/javascript`, `p/typescript`, `r/javascript.lang.security`, `r/javascript.browser.security` (SQL, command, XSS and template injection rules); Bandit B608, B602, B605, B307, B102, B703; no ESLint security plugin runs, so rely on Semgrep and manual review. A scanner hit is a lead, not a finding.

**Manual checks:** Trace each source (request params, headers, files, queue messages, DB values) to sinks (queries, shell, eval, templates, DOM); verify parameterization, allowlists, output encoding and CSP; check ORM escape hatches; validate that sanitizers are applied on every path.

**Rolls up to:** SEC-03, SEC-14, SEC-12, SEC-05, CODE-10, CODE-08

### A06:2025 Insecure Design

**Python:** Missing rate limits on login/reset/OTP; business-logic flaws (price or quantity from client, negative amounts, race conditions on balances); no tenant model; trust boundaries not defined; weak password reset flows; unbounded resource use by design.

**JS/TS/Node/frontend:** Client-computed prices or permissions accepted by API; no server-side validation behind form validation; no throttling on Express/Next.js API routes; multi-step flows skippable by calling later endpoints directly; secrets or decisions placed in the SPA.

**Scanner leads:** Scanners rarely detect design flaws. Semgrep rules (e.g. missing rate limiters, mass assignment) give weak leads only; Checkov may show missing network segmentation. Treat all hits as leads and rely on manual review. A scanner hit is a lead, not a finding.

**Manual checks:** Review threat model or its absence; trace critical workflows (signup, reset, payment, role change) for abuse cases; check rate limiting and anti-automation, idempotency, race conditions (check-then-act), server-side enforcement of business rules, tenant isolation by design, fail-safe defaults.

**Rolls up to:** ARC-06, ARC-12, ARC-14, SEC-07, SEC-16, SEC-02, SEC-10, DATA-03, DATA-04, SEC-15, PERF-10

### A07:2025 Authentication Failures

**Python:** Django custom auth without lockout or password validators; session fixation; Flask `SECRET_KEY` weak or committed; JWT without expiry or verification; passwords compared with `==`; password reset tokens predictable or non-expiring; MFA absent for admin.

**JS/TS/Node/frontend:** Express sessions without `secure/httpOnly/sameSite`; JWT stored in `localStorage`; NextAuth/Passport misconfiguration (missing `NEXTAUTH_SECRET`, open callbacks); login without throttling; user enumeration via error messages; tokens in URLs.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/cwe-top-25`, `p/python`, `p/javascript` (JWT verification and session rules); Bandit B105-B107 (hardcoded passwords); Gitleaks (redacted) for committed credentials. A scanner hit is a lead, not a finding.

**Manual checks:** Verify auth at every entry point including APIs, websockets, webhooks; session/token lifetime, rotation and revocation on logout and password change; password storage; brute-force protection; MFA for privileged users; reset and magic-link entropy, expiry, single use; account enumeration; default accounts.

**Rolls up to:** SEC-01, SEC-16, SEC-06, SEC-04, SEC-07, SEC-17, SEC-05

### A08:2025 Software or Data Integrity Failures

**Python:** `pickle.loads`, `yaml.load` without SafeLoader (Bandit B301, B506), `marshal`, `shelve` on untrusted data; unsigned update or plugin download; unverified webhook signatures; CI artifacts unsigned.

**JS/TS/Node/frontend:** `node-serialize`, `eval(JSON)`, unsafe `JSON.parse` revivers; prototype pollution via `merge`; CDN scripts without SRI; webhook handlers without HMAC verification; auto-update without signature; untrusted `npm` postinstall.

**Scanner leads:** Bandit B301, B302, B403, B506; Semgrep `p/python`, `p/javascript`, `r/python.lang.security.audit`; zizmor and actionlint (unpinned actions, artifact poisoning, `pull_request_target`); Hadolint for downloads without checksum; OSV-Scanner and Trivy for vulnerable serializers. A scanner hit is a lead, not a finding.

**Manual checks:** Identify every deserialization and dynamic-load point and its data source; verify signatures on webhooks, packages and artifacts; check CI pipeline integrity (pinned actions, protected branches, provenance); SRI on third-party scripts; build-once-promote.

**Rolls up to:** SEC-14, SEC-06, DEP-05, CICD-05, CICD-09, CICD-10, DATA-08, DATA-11, SEC-15

### A09:2025 Security Logging and Alerting Failures

**Python:** No audit log of login failures, permission changes, data export; logging of passwords, tokens or PII (`logger.info(request.POST)`); log injection through unsanitized newlines; `except: pass` hiding security errors; no alerting integration.

**JS/TS/Node/frontend:** `console.log(req.body)` with secrets; no request IDs; errors swallowed in Express handlers; Sentry or logging off in production; client-side errors not captured; no alert on auth failures.

**Scanner leads:** Gitleaks for secrets committed in log fixtures (it cannot see runtime logs); Bandit B110 and B112 (try/except pass); Checkov for disabled cloud logging (CloudTrail, flow logs); sensitive data in logs is manual. A scanner hit is a lead, not a finding.

**Manual checks:** Confirm security events are logged with who/what/when, without secrets; logs are protected and retained; alerts exist, have owners and runbooks; log injection prevented; telemetry covers auth, authorization denial, admin actions, and failed jobs.

**Rolls up to:** SEC-17, OBS-01, OBS-06, OBS-07, OBS-08, OBS-14, SEC-08, SEC-04, INFRA-04

### A10:2025 Mishandling of Exceptional Conditions

**Python:** Bare `except:`/`except Exception: pass` (Bandit B110, B112); failing open on auth or validation errors; stack traces returned to clients; unhandled exceptions in async tasks; missing transaction rollback; `assert` used for security checks (B101); resources not released on error.

**JS/TS/Node/frontend:** Unhandled promise rejections; `catch {}` swallowing errors; Express async handlers without error middleware; fail-open `try { verify } catch { next() }`; missing `error.tsx`/error boundaries in Next.js/React; timeouts and retries absent on external calls.

**Scanner leads:** Bandit B101, B110, B112; Semgrep `p/python`, `p/javascript`, `p/typescript` (empty catch, unhandled promise); Ruff for bare-except (E722, BLE001) when the project enables them; Lizard flags complex error-handling functions only as leads. A scanner hit is a lead, not a finding.

**Manual checks:** Check that errors on security-relevant paths fail closed; user-facing errors are generic while details are logged; transactions roll back and resources close; async/background failures are surfaced; timeouts, retries, circuit breakers and resource exhaustion handled; global error handlers exist.

**Rolls up to:** CODE-04, CODE-05, SEC-18, OBS-07, PERF-02, PERF-09, PERF-11, DATA-03, SEC-01
