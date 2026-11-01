# D03 Security and privacy — checklist

Questions: see methodology.md §4 D03. This file says how to answer them. Standards coverage (all OWASP Top 10:2025 categories and all CWE Top 25 entries) uses `references/owasp-top10-2025.md` and `references/cwe-top25.md`; framework sinks and entry points are in `references/profile-python.md`, `references/profile-javascript.md`, and AI-specific checks in `references/profile-ai-agents.md`.

Every Semgrep/Bandit/Gitleaks hit in `leads.json` is a lead: read the code path, check reachability from an entry point and existing mitigations, then decide. Claims of absence (no auth, no rate limit) need the inspected search space and a check for global middleware, platform features (API gateway, Vercel/Cloudflare), and framework defaults. Never copy a secret value; cite the Gitleaks lead id and file:line only.

### SEC-01
**How to check (Python):** Django: `AUTHENTICATION_BACKENDS`, `SESSION_COOKIE_AGE`, `SESSION_EXPIRE_AT_BROWSER_CLOSE`, DRF `DEFAULT_AUTHENTICATION_CLASSES`. FastAPI: the `get_current_user` dependency — does it verify JWT signature, `exp`, `aud`/`iss`, algorithm list (`jwt.decode(..., algorithms=["HS256"])`)? Flask-Login `login_required` coverage.
**How to check (JS/TS):** `jsonwebtoken.verify` with `algorithms`, never `jwt.decode` as verification; NextAuth/Auth.js `callbacks.session`/`jwt`; Passport strategies; refresh-token rotation and expiry; Next.js `middleware.ts` matcher gaps (`/api` excluded, static matcher missing new routes).
**Evidence to cite:** Auth setup file:line, token validation lines, and any entry point reachable without it.
**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/cwe-top-25` (JWT none-alg, unverified decode); Bandit B105–B107.
**Common false positives:** Routes protected by an upstream gateway or platform auth (documented in IaC); intentionally public endpoints.

### SEC-02
**How to check (Python):** For each object fetch by ID (`Model.objects.get(pk=...)`, `session.get(Model, id)`), check the owner/tenant filter or `get_queryset` scoping in DRF; `has_object_permission`; role checks on mutation endpoints; service-role DB connections bypassing RLS.
**How to check (JS/TS):** `findUnique({ where: { id } })` / `findById(req.params.id)` without `userId`/`orgId`; Next.js server actions and route handlers trusting `userId` from the body; Supabase `service_role` key in request paths; UI-only role gating.
**Evidence to cite:** Entry file:line → query file:line lacking the scope, and the identifier the attacker controls.
**Scanner leads:** Semgrep `p/owasp-top-ten` (IDOR-adjacent patterns are weak); mostly manual — no scanner proves missing authorization.
**Common false positives:** Queries already scoped by a tenant-aware manager, middleware, or RLS policy; IDs that are unguessable and documented as capability links (still note the risk).

### SEC-03
**How to check (Python):** `cursor.execute(f"...")`, `.raw()`, `.extra()`, `text(f"...")`; `subprocess` with `shell=True` or user-built argv; `open(user_path)`; templates with `|safe`, `mark_safe`, `Markup`; XML parsing with `lxml`/`xml.etree` on untrusted input.
**How to check (JS/TS):** Template-literal SQL in `pg`/`mysql2`/`knex.raw`/`prisma.$queryRawUnsafe`; Mongo `find(req.body)` operator injection; `child_process.exec`/`spawn(..., {shell: true})`; `res.send(userInput)` HTML; `path.join(root, req.params.file)`.
**Evidence to cite:** Source (input) file:line → sink file:line, and whether parameterization or encoding is present.
**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/cwe-top-25`, `r/python.lang.security.audit`, `r/javascript.lang.security`; Bandit B608, B602, B605, B313–B319 (lxml is no longer flagged by Bandit; check `XMLParser(resolve_entities=...)` manually).
**Common false positives:** Interpolating constants or allowlisted identifiers (column names from a fixed map); ORM query builders; `shell=True` with a fully constant string.

### SEC-04
**How to check (Python):** Gitleaks leads (working tree and history); `SECRET_KEY = "..."` in settings; keys in `settings.py`, `config.py`, notebooks, fixtures; secrets logged (`logger.info(f"token={...}")`) or returned in errors; `.env` committed.
**How to check (JS/TS):** Same; also secrets in `next.config.js` `env`, `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variables holding private keys, keys in `public/` or source maps, tokens in URLs.
**Evidence to cite:** Gitleaks lead id, rule id, and file:line only (values are redacted; never reproduce them); whether the secret is in history only.
**Scanner leads:** Gitleaks (always `--redact`); Bandit B105–B107; Semgrep `p/python`, `p/javascript`.
**Common false positives:** Test fixtures with fake high-entropy strings, example placeholders (`changeme`, `xxx`), public keys, publishable keys (Stripe `pk_`, Firebase web config) that are public by design.

### SEC-05
**How to check (Python):** Django `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `CSRF_TRUSTED_ORIGINS`, `@csrf_exempt`; `django-cors-headers` `CORS_ALLOW_ALL_ORIGINS` with credentials; FastAPI `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`; hashing (`hashlib.md5/sha1` for passwords), `verify=False`.
**How to check (JS/TS):** `helmet()` presence, `cors({ origin: true, credentials: true })`, `cookie` options (`httpOnly`, `secure`, `sameSite`), CSRF protection for cookie sessions (`csurf` is deprecated), Next.js `headers()` CSP, `crypto.createHash('md5')`, `rejectUnauthorized: false`.
**Evidence to cite:** Config file:line per control and the environment it applies to (dev vs prod settings).
**Scanner leads:** Bandit B303, B324, B501, B502–B505, B323; Semgrep `p/owasp-top-ten`, `p/cwe-top-25`; Checkov for TLS in IaC.
**Common false positives:** MD5/SHA1 for non-security checksums (cache keys, ETags); CORS `*` on a public read-only API without cookies; headers set by a CDN or ingress (check config).

### SEC-06
**How to check (Python):** Django admin URL and `is_staff` checks; DRF admin viewsets; Celery tasks invoked by HTTP endpoints; webhook views: signature verification (`stripe.Webhook.construct_event`, HMAC compare with `hmac.compare_digest`) before parsing; internal endpoints protected only by "not linked".
**How to check (JS/TS):** `/api/admin/*`, `/internal/*` routes, cron endpoints (`/api/cron` on Vercel without `CRON_SECRET` check), webhook handlers verifying signatures on the raw body (`express.raw`), `timingSafeEqual`.
**Evidence to cite:** Each privileged entry file:line and its independent auth check (or lack).
**Scanner leads:** Semgrep `p/owasp-top-ten`; mostly manual.
**Common false positives:** Endpoints only reachable on a private network declared in IaC (state it as an assumption).

### SEC-07
**How to check (Python):** `django-ratelimit`, `slowapi`, `flask-limiter`, DRF throttling classes on login, signup, password reset, OTP, search, export and paid-API endpoints; `DATA_UPLOAD_MAX_MEMORY_SIZE`; nonce/timestamp checks on webhooks.
**How to check (JS/TS):** `express-rate-limit`, `@fastify/rate-limit`, Upstash ratelimit in Next.js middleware; `express.json({ limit })`; in-memory limiters behind multiple instances (ineffective).
**Evidence to cite:** Costly/public endpoint file:line and the limiter config (or its absence after checking platform config).
**Scanner leads:** none — manual.
**Common false positives:** Limits enforced at the WAF/API gateway/Cloudflare level declared in IaC or docs (record as needs_verification if only documented).

### SEC-08
**How to check (Python):** Models with PII (email, phone, address, DOB, documents); serializers exposing them; logging of request bodies; Sentry `send_default_pii=True`; retention jobs; analytics calls with user data.
**How to check (JS/TS):** Same in Prisma/TypeORM models, API responses, `console.log(req.body)`, analytics SDKs (Segment, PostHog) receiving PII, Sentry `sendDefaultPii`.
**Evidence to cite:** Field definitions and the flows that copy them to logs, telemetry or third parties.
**Scanner leads:** none — manual.
**Common false positives:** PII flowing to processors required for the feature (payment, email provider) with a documented basis.

### SEC-09
**How to check (Python):** For each security lead and OSV advisory, trace from an entry point to the vulnerable call; check input constraints, auth in front of it, and feature flags.
**How to check (JS/TS):** Same; for frontend packages, check whether the vulnerable function is in client code and whether user input reaches it.
**Evidence to cite:** Lead id, the reachability trace (file:line chain) or the mitigation that blocks it.
**Scanner leads:** All security leads (Semgrep, Bandit, OSV-Scanner, Gitleaks) are inputs here.
**Common false positives:** Dev-only dependencies, test code, vulnerable functions never imported.

### SEC-10
**How to check (Python):** If inventory `ai_sdks` is non-empty, apply `references/profile-ai-agents.md`; otherwise `not_applicable` with that reason.
**How to check (JS/TS):** Same (Vercel AI SDK `tools`, OpenAI/Anthropic tool calling, LangChain.js agents).
**Evidence to cite:** Tool definitions file:line, the untrusted input that reaches the prompt, and the authorization on each tool action.
**Scanner leads:** none — manual.
**Common false positives:** Read-only tools over public data; tools whose actions require a separate user confirmation step that is enforced server-side.

### SEC-11
**How to check (Python):** `requests.get(user_url)`, `httpx`, `urllib.request.urlopen`, PDF renderers (WeasyPrint, wkhtmltopdf) and image fetchers given user URLs; check scheme/host allowlists, `allow_redirects`, resolution of private IPs (169.254.169.254, 10/8, ::1).
**How to check (JS/TS):** `fetch(req.body.url)`, `axios.get(url)`, Puppeteer `page.goto(userUrl)`, Next.js `images.remotePatterns` with `**` wildcards, link-preview services.
**Evidence to cite:** Entry file:line where the URL enters and the fetch file:line; the validation (or lack) and redirect handling.
**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/cwe-top-25` (SSRF rules); Bandit B310.
**Common false positives:** URLs from server config or a fixed allowlist; fetches running in an isolated egress-restricted service (needs IaC evidence).

### SEC-12
**How to check (Python):** `Model(**request.json)`, `serializer = ...(fields="__all__")`, `ModelForm` with `fields = "__all__"` or `exclude`, Pydantic models reused for input and DB with `role`/`is_admin`; responses returning ORM objects without `response_model`.
**How to check (JS/TS):** `Object.assign(user, req.body)`, `prisma.user.update({ data: req.body })`, spread of body into create calls, returning full DB rows (`res.json(user)`) including `passwordHash`.
**Evidence to cite:** Binding file:line and the sensitive field that can be set or leaked.
**Scanner leads:** Semgrep `p/owasp-top-ten` (mass-assignment rules exist for some frameworks); mostly manual.
**Common false positives:** Explicit `fields = [...]` allowlists; DTOs with `whitelist: true` / `forbidNonWhitelisted` in NestJS `ValidationPipe`.

### SEC-13
**How to check (Python):** Django `FileField` `upload_to`, `MEDIA_ROOT` served by the app, `FileResponse(open(path))` with user input, `os.path.join(BASE, filename)` without normalization, S3 presigned URL expiry, `secure_filename` in Flask.
**How to check (JS/TS):** `multer` limits and `fileFilter`, storing under `public/`, `res.sendFile(req.query.path)`, `Content-Disposition` built from user filenames, presigned URL `Expires`.
**Evidence to cite:** Upload/download handler file:line, the limits, storage location, and path handling.
**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/cwe-top-25` (path traversal); Bandit B108 (temp paths).
**Common false positives:** Paths built from server-generated UUIDs; uploads streamed directly to object storage with server-side type checks.

### SEC-14
**How to check (Python):** `pickle.loads`, `joblib.load`, `yaml.load` without `SafeLoader`, `eval`/`exec`, `jinja2.Template(user_string)` or `render_template_string(user_input)`, `marshal`, `shelve` on untrusted data.
**How to check (JS/TS):** `eval`, `new Function`, `vm.runInContext` (not a sandbox), `node-serialize`, Handlebars/EJS compiled from user input, `lodash.merge`/deep-merge of `req.body`, `qs` with deep nesting creating `__proto__` keys.
**Evidence to cite:** Sink file:line and the origin of the data (user input, uploaded file, cache, queue).
**Scanner leads:** Bandit B301, B403, B506, B307, B102, B701; Semgrep `r/python.lang.security.audit`, `r/javascript.lang.security`, `p/cwe-top-25`.
**Common false positives:** Pickle of data the service itself wrote to a private store (still note the trust assumption); `yaml.load` with `Loader=yaml.SafeLoader`.

### SEC-15
**How to check (Python):** Usually `not_applicable` for API-only backends; for Django templates check `|safe` and `autoescape off` blocks.
**How to check (JS/TS):** `grep -rn "NEXT_PUBLIC_\|VITE_\|REACT_APP_"` and confirm none hold private secrets; `dangerouslySetInnerHTML`, `v-html`, `innerHTML =`, `href={userUrl}` (`javascript:`); tokens in `localStorage`; role checks that only hide buttons while the API allows the action.
**Evidence to cite:** Env/var file:line, the sink file:line and the data source; the API route that lacks the server-side check.
**Scanner leads:** Semgrep `r/javascript.browser.security`, `p/typescript`, `p/javascript`; Gitleaks for keys in bundles committed to the repo.
**Common false positives:** HTML sanitized with DOMPurify before the sink; public publishable keys; `localStorage` for non-sensitive preferences.

### SEC-16
**How to check (Python):** Django `PasswordResetTokenGenerator` and `PASSWORD_RESET_TIMEOUT`; custom tokens from `random` vs `secrets.token_urlsafe`; single-use enforcement; login/reset responses that differ for unknown emails; `update_session_auth_hash`/session flush on password change.
**How to check (JS/TS):** Token generation (`crypto.randomBytes` vs `Math.random`), expiry and deletion after use, magic-link reuse, email change without verifying the new address, JWTs not revocable after role change (no token version).
**Evidence to cite:** Token creation and consumption file:line; the response branches that enumerate accounts.
**Scanner leads:** Bandit B311; Semgrep `p/cwe-top-25`; mostly manual.
**Common false positives:** Flows delegated entirely to a managed provider (Auth0, Cognito, Clerk) — check its config only, and note what cannot be seen.

### SEC-17
**How to check (Python):** Look for an audit model/table (`AuditLog`, `django-auditlog`, `django-simple-history`) written on sign-in, failed sign-in (`user_login_failed` signal), permission changes, admin actions (`LogEntry`), exports.
**How to check (JS/TS):** Same in Prisma/TypeORM models or an external audit sink; NextAuth `events` callbacks; separation from `console.log` debug output.
**Evidence to cite:** The events recorded (file:line) and the ones that are not; who can modify or delete the records.
**Scanner leads:** none — manual.
**Common false positives:** Provider-side audit logs (Auth0, cloud IAM) cover sign-in events; note them as external.

### SEC-18
**How to check (Python):** `DEBUG = True` defaults or `DEBUG = os.environ.get("DEBUG", True)`, `ALLOWED_HOSTS = ["*"]`, FastAPI `docs_url` enabled in prod, Flask `debug=True`, Werkzeug debugger, `/admin` exposed, DRF browsable API in prod, default passwords in `docker-compose.yml`.
**How to check (JS/TS):** `productionBrowserSourceMaps: true`, error handlers returning `err.stack`, GraphQL introspection/playground in prod, `/api/debug` routes, default DB credentials in compose and `.env.example` reused in deploy config.
**Evidence to cite:** Setting file:line and how the production value is chosen (env var default, settings split).
**Scanner leads:** Bandit B201, B104; Semgrep `p/python`, `p/owasp-top-ten`; Checkov for compose/K8s; Gitleaks for default credentials.
**Common false positives:** Debug settings in `settings/dev.py` or `local` profiles never loaded in production (verify how production selects settings).
