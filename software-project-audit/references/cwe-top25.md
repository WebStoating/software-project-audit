# CWE Top 25 (2025) coverage

Source: https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html (index: https://cwe.mitre.org/top25/). Retrieved 2026-10-27. Each CWE needs a coverage outcome. Memory-safety CWEs are normally `not_applicable` for Python and JS/TS unless native code is in scope; give the reason in the coverage entry. Scanner hits are leads, not findings. Check IDs refer to `methodology.md`.

### CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

**Rank:** 1

**Python:** Jinja `|safe`, Django `mark_safe`/`format_html` misuse, `autoescape off`, Flask `Markup(user)`, f-string HTML responses (Bandit B703, B701).

**JS/TS/Node/frontend:** React `dangerouslySetInnerHTML`, Vue `v-html`, `innerHTML`/`insertAdjacentHTML`/`document.write`, unsanitized `href`/`src`, Next.js raw HTML in MDX, server-rendered templates (EJS `<%-`).

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/cwe-top-25`, `p/python`, `r/javascript.browser.security`, `p/typescript` (XSS sinks in templates, React, Vue); Bandit B703, B701, B704. A scanner hit is a lead, not a finding.

**Manual checks:** Trace user and stored data to HTML/DOM sinks; confirm encoding or a sanitizer (DOMPurify) and CSP.

**Rolls up to:** SEC-03, SEC-05, SEC-15

### CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

**Rank:** 2

**Python:** f-string/`%`/`.format` SQL in `cursor.execute`, Django `.raw()`/`.extra()`/`RawSQL`, SQLAlchemy `text(f'...')` (Bandit B608).

**JS/TS/Node/frontend:** Template-string queries with `pg`, `mysql2`, `knex.raw`, Sequelize/Prisma `$queryRawUnsafe`; NoSQL operator injection.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/cwe-top-25`, `r/python.lang.security.audit`, `r/javascript.lang.security`; Bandit B608. A scanner hit is a lead, not a finding.

**Manual checks:** Confirm parameterized queries everywhere including ORDER BY/column names (allowlist); review raw-SQL helpers.

**Rolls up to:** SEC-03, DATA-05, CODE-10

### CWE-352 Cross-Site Request Forgery (CSRF)

**Rank:** 3

**Python:** Django `@csrf_exempt`, missing `CsrfViewMiddleware`; Flask without Flask-WTF `CSRFProtect`; FastAPI cookie-session endpoints without tokens.

**JS/TS/Node/frontend:** Express cookie sessions without `csurf`-style tokens or SameSite; Next.js route handlers/server actions with cookie auth on state-changing GET; SPA with cookies and permissive CORS.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/python` (Django csrf-exempt, Flask CSRF rules), `p/javascript`; Bandit has no CSRF rule. A scanner hit is a lead, not a finding.

**Manual checks:** List state-changing endpoints using cookie auth; verify tokens or SameSite=Lax/Strict plus Origin checks; GET must be safe.

**Rolls up to:** SEC-05, SEC-01, SEC-15

### CWE-862 Missing Authorization

**Rank:** 4

**Python:** Django views/DRF with `AllowAny` or default permissions; Flask routes with only `@login_required` and no role/owner check; FastAPI routers lacking dependencies.

**JS/TS/Node/frontend:** Express routers without authorization middleware; Next.js API routes/server actions that check login but not role or ownership; admin UI hidden only in React.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/cwe-top-25`, `p/python`, `p/typescript` (missing-auth leads); no scanner proves absence. A scanner hit is a lead, not a finding.

**Manual checks:** Enumerate routes and verify the authorization decision for each action and object, including background jobs and internal APIs.

**Rolls up to:** SEC-02, SEC-06, ARC-12, DATA-05

### CWE-787 Out-of-bounds Write

**Rank:** 5

**Python:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM).

**JS/TS/Node/frontend:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM). If native code is in scope, check bounds and lifetime manually.

**Scanner leads:** Semgrep/Bandit do not cover native memory bugs; Bandit B1xx ctypes hints only. A scanner hit is a lead, not a finding.

**Manual checks:** Confirm whether any native extension, ctypes/cffi or node-gyp addon is in scope; if not, record `not_applicable`.

**Rolls up to:** SEC-09, DEP-02, DEP-03

### CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

**Rank:** 6

**Python:** `open(os.path.join(base, user))`, `send_file(user_path)`, `tarfile.extractall`/`zipfile.extractall` (Bandit B202), Django `FileResponse` with user path, FastAPI `FileResponse`.

**JS/TS/Node/frontend:** `fs.readFile(req.params.x)`, `res.sendFile` without root, `path.join` with user input, `express.static` dotfiles, zip-slip in extractors, Next.js dynamic file routes.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/python`, `r/javascript.lang.security` (path-traversal rules); Bandit B202, B108. A scanner hit is a lead, not a finding.

**Manual checks:** Check resolved paths are confined (`realpath` prefix check, `safe_join`), upload names sanitized, archives validated, symlinks handled.

**Rolls up to:** SEC-13, SEC-03

### CWE-416 Use After Free

**Rank:** 7

**Python:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM).

**JS/TS/Node/frontend:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM). If native code is in scope, check bounds and lifetime manually.

**Scanner leads:** None applicable for pure Python/JS code. A scanner hit is a lead, not a finding.

**Manual checks:** Only if native extensions are in scope: review ownership and lifetime of buffers and handles.

**Rolls up to:** SEC-09, DEP-02

### CWE-125 Out-of-bounds Read

**Rank:** 8

**Python:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM).

**JS/TS/Node/frontend:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM). If native code is in scope, check bounds and lifetime manually.

**Scanner leads:** None applicable for pure Python/JS code. A scanner hit is a lead, not a finding.

**Manual checks:** Only if native extensions are in scope; also note Python/JS bounds errors surface as exceptions (see CWE-20 / error handling).

**Rolls up to:** SEC-09, DEP-02

### CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')

**Rank:** 9

**Python:** `os.system`, `subprocess.*(shell=True)`, `os.popen`, `commands` with interpolated input (Bandit B602, B604, B605, B607).

**JS/TS/Node/frontend:** `child_process.exec/execSync` with template strings, `shell: true` in `spawn`, build scripts calling shell with env input.

**Scanner leads:** Semgrep `p/cwe-top-25`, `r/python.lang.security.audit`, `r/javascript.lang.security`; Bandit B602, B603, B605, B606, B607. A scanner hit is a lead, not a finding.

**Manual checks:** Prefer argv lists; confirm inputs allowlisted; look for filename/argument injection (leading `-`) even without a shell.

**Rolls up to:** SEC-03, CODE-08, CICD-09

### CWE-94 Improper Control of Generation of Code ('Code Injection')

**Rank:** 10

**Python:** `eval`, `exec`, `compile`, `__import__` on user data (Bandit B307, B102), server-side template injection (`render_template_string`, Jinja `Template(user)`).

**JS/TS/Node/frontend:** `eval`, `new Function`, `vm.runInContext`, `setTimeout(string)`, template engines compiling user templates, dynamic `require(userInput)`.

**Scanner leads:** Semgrep `p/python`, `p/javascript`, `r/javascript.lang.security` (eval, SSTI); Bandit B307, B102, B701. A scanner hit is a lead, not a finding.

**Manual checks:** Find every dynamic evaluation point and its data source; replace with data-driven dispatch.

**Rolls up to:** SEC-14, SEC-03, CODE-08

### CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')

**Rank:** 11

**Python:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM).

**JS/TS/Node/frontend:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM). If native code is in scope, check bounds and lifetime manually.

**Scanner leads:** None applicable for pure Python/JS code. A scanner hit is a lead, not a finding.

**Manual checks:** Only for native extensions in scope.

**Rolls up to:** SEC-09, DEP-02

### CWE-434 Unrestricted Upload of File with Dangerous Type

**Rank:** 12

**Python:** Django `FileField` without validators, Flask `request.files` saved with user filename, FastAPI `UploadFile` unchecked, uploads stored in web root or served with sniffable type.

**JS/TS/Node/frontend:** multer/formidable with no `fileFilter`/size limit, Next.js upload routes writing to `public/`, trusting `Content-Type`/extension, SVG/HTML uploads served inline.

**Scanner leads:** Semgrep `p/python`, `p/javascript` (upload rules, limited); no dedicated Bandit rule; mostly manual. A scanner hit is a lead, not a finding.

**Manual checks:** Verify size and type validation by content, randomized names, storage outside web root or on object storage, `Content-Disposition`, malware scanning where relevant.

**Rolls up to:** SEC-13, PERF-05, SEC-03

### CWE-476 NULL Pointer Dereference

**Rank:** 13

**Python:** Usually `not_applicable` for Python/JS in the memory sense - reason: managed memory. The analogue (`None`/`undefined` access raising AttributeError/TypeError) is a robustness defect: check optional returns and unchecked `.get()` results. Native extensions in scope: manual review.

**JS/TS/Node/frontend:** Analogue is `undefined`/`null` property access (TypeError); check optional chaining, TypeScript `strict`/`strictNullChecks`. Memory-safety form applies only to native addons in scope.

**Scanner leads:** Ruff/TypeScript strict flags for Optional misuse; Semgrep has few null rules; Lizard not relevant. A scanner hit is a lead, not a finding.

**Manual checks:** Decide `not_applicable` for memory-safety sense; separately assess null-handling robustness under code quality.

**Rolls up to:** CODE-03, CODE-04, CODE-09

### CWE-121 Stack-based Buffer Overflow

**Rank:** 14

**Python:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM).

**JS/TS/Node/frontend:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM). If native code is in scope, check bounds and lifetime manually.

**Scanner leads:** None applicable for pure Python/JS code. A scanner hit is a lead, not a finding.

**Manual checks:** Only for native extensions in scope.

**Rolls up to:** SEC-09, DEP-02

### CWE-502 Deserialization of Untrusted Data

**Rank:** 15

**Python:** `pickle.load(s)`, `cPickle`, `marshal`, `shelve`, `yaml.load` without SafeLoader, `jsonpickle`, Django signed-cookie pickle serializer (Bandit B301, B302, B506).

**JS/TS/Node/frontend:** `node-serialize`, `serialize-javascript` misuse, `vm`-based revivers, YAML `load` with unsafe schema, prototype-polluting deep merges, unsafe `JSON.parse` reviver logic.

**Scanner leads:** Bandit B301, B302, B403, B506; Semgrep `p/python`, `r/javascript.lang.security`; OSV-Scanner and Trivy for vulnerable serializer versions. A scanner hit is a lead, not a finding.

**Manual checks:** Identify all deserialization points, their sources (cache, queue, uploads, cookies); use safe formats and signatures.

**Rolls up to:** SEC-14, SEC-06, DEP-02

### CWE-122 Heap-based Buffer Overflow

**Rank:** 16

**Python:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM).

**JS/TS/Node/frontend:** Usually `not_applicable` for Python/JS - reason: managed memory; applicable only to native extensions in scope (C/C++/Rust extensions, ctypes/cffi, node-gyp/N-API addons, WASM). If native code is in scope, check bounds and lifetime manually.

**Scanner leads:** None applicable for pure Python/JS code. A scanner hit is a lead, not a finding.

**Manual checks:** Only for native extensions in scope.

**Rolls up to:** SEC-09, DEP-02

### CWE-863 Incorrect Authorization

**Rank:** 17

**Python:** Ownership check present but wrong (compares wrong field, checks only `is_authenticated`), role checks on view but not on related objects, DRF `get_queryset` unscoped, tenant filter skipped in raw SQL.

**JS/TS/Node/frontend:** Express/Next.js checks on client-supplied role/ID, authorization only on list route but not detail/update, JWT claims trusted without server lookup, GraphQL resolvers lacking field-level checks.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/python`, `p/typescript` leads; no scanner verifies correctness of a policy. A scanner hit is a lead, not a finding.

**Manual checks:** Review authorization logic and tests for each protected action, including negative cases and cross-tenant access.

**Rolls up to:** SEC-02, SEC-06, DATA-05, TEST-03

### CWE-20 Improper Input Validation

**Rank:** 18

**Python:** No Pydantic/serializer/form validation on request data; trusting `request.GET` types; missing length and range checks; FastAPI models with `Any`.

**JS/TS/Node/frontend:** No Zod/Joi/Yup validation in Express or Next.js handlers; client-only validation; trusting `req.body` shapes; `parseInt` without checks.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/python`, `p/javascript`; Bandit partial (B105 family unrelated); Ruff/TS strict for types. A scanner hit is a lead, not a finding.

**Manual checks:** Check validation at each boundary (HTTP, queue, file, env), server-side, with allowlists, size limits, and typed models.

**Rolls up to:** CODE-10, CODE-03, SEC-03, SEC-12

### CWE-284 Improper Access Control

**Rank:** 19

**Python:** Umbrella category: Django/Flask/FastAPI missing or inconsistent permission checks, overly broad CORS, file permissions (`os.chmod 0o777`, Bandit B103), exposed admin.

**JS/TS/Node/frontend:** Express/Next.js missing authorization, `cors` wildcard with credentials, public storage buckets, client-side-only gating.

**Scanner leads:** Semgrep `p/owasp-top-ten`; Bandit B103; Checkov (IAM, bucket ACLs, security groups). A scanner hit is a lead, not a finding.

**Manual checks:** Map assets to access rules; verify enforcement server-side and in infrastructure (IAM, network).

**Rolls up to:** SEC-02, SEC-06, INFRA-02, INFRA-03, ARC-06

### CWE-200 Exposure of Sensitive Information to an Unauthorized Actor

**Rank:** 20

**Python:** Debug pages and tracebacks in responses, serializers returning all fields (`fields='__all__'`, password hash), PII in logs, secrets in repo, verbose errors, `.env` committed.

**JS/TS/Node/frontend:** API returning full DB rows, source maps and `NEXT_PUBLIC_*` secrets, `console.log` of tokens, GraphQL introspection and overfetching, secrets in client bundles.

**Scanner leads:** Gitleaks (always `--redact`); Semgrep `p/cwe-top-25`, `p/python` (Django debug and settings rules); Bandit B105-B107; Checkov for public storage. A scanner hit is a lead, not a finding.

**Manual checks:** Review response serializers, error handling, logging, client bundles, backups and artifacts, data classification and retention.

**Rolls up to:** SEC-04, SEC-08, SEC-15, SEC-18, DATA-15, OBS-08

### CWE-306 Missing Authentication for Critical Function

**Rank:** 21

**Python:** Admin/management endpoints, webhooks, health/debug/metrics routes, Celery or internal APIs without auth; FastAPI routes lacking `Depends`.

**JS/TS/Node/frontend:** Express admin routes, Next.js API routes and server actions callable anonymously, unauthenticated websockets, exposed internal tools.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/python`, `p/javascript` leads; Checkov for public exposure. A scanner hit is a lead, not a finding.

**Manual checks:** List critical functions (admin, payments, export, reset) and verify authentication at the server on each; check webhooks use signatures.

**Rolls up to:** SEC-01, SEC-06, INFRA-13, ARC-12

### CWE-918 Server-Side Request Forgery (SSRF)

**Rank:** 22

**Python:** `requests.get(user_url)`, `urllib.request.urlopen` (Bandit B310), `httpx` on user URLs, webhook and image-fetch features without allowlists.

**JS/TS/Node/frontend:** `fetch`/`axios.get(req.query.url)`, link-preview and PDF/screenshot services, Next.js image `remotePatterns` too broad, redirect following.

**Scanner leads:** Semgrep `p/owasp-top-ten`, `p/python`, `r/javascript.lang.security` (SSRF rules); Bandit B310. A scanner hit is a lead, not a finding.

**Manual checks:** Check URL allowlists, blocking of private/link-local/metadata ranges, DNS rebinding, redirect handling, egress controls.

**Rolls up to:** SEC-11, INFRA-03, PERF-09

### CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')

**Rank:** 23

**Python:** Command, argument, header, CSV/formula and template injection; `subprocess` with user-controlled arguments (Bandit B603, B602).

**JS/TS/Node/frontend:** `child_process` args, `git`/`curl` wrappers with user input, header injection via `res.setHeader`, CSV export formulas.

**Scanner leads:** Semgrep `p/cwe-top-25`, `r/python.lang.security.audit`, `r/javascript.lang.security`; Bandit B602-B607. A scanner hit is a lead, not a finding.

**Manual checks:** Same as CWE-78; also check argument injection with leading `-` and neutralization of delimiters in generated commands.

**Rolls up to:** SEC-03, CODE-08

### CWE-639 Authorization Bypass Through User-Controlled Key

**Rank:** 24

**Python:** IDOR: `Model.objects.get(pk=request.GET['id'])`, DRF detail views without owner-scoped queryset, predictable sequential IDs.

**JS/TS/Node/frontend:** `findById(req.params.id)` without owner check, Next.js `[id]` routes, GraphQL node lookups, signed URLs reused across users.

**Scanner leads:** Semgrep `p/owasp-top-ten` (idor leads, weak); no scanner confirms. A scanner hit is a lead, not a finding.

**Manual checks:** For every endpoint taking an object ID, confirm the query is scoped to the caller/tenant; prefer UUIDs plus checks.

**Rolls up to:** SEC-02, DATA-05, TEST-03

### CWE-770 Allocation of Resources Without Limits or Throttling

**Rank:** 25

**Python:** No request size limits (`DATA_UPLOAD_MAX_MEMORY_SIZE`), unbounded pagination, `requests` without timeout (Bandit B113), regex DoS, unbounded queues/threads, no rate limiting.

**JS/TS/Node/frontend:** Express without `body-parser` limits or rate limiting, unbounded `limit` params, GraphQL depth, `Promise.all` over unbounded input, ReDoS, memory-buffered uploads.

**Scanner leads:** Bandit B113; Semgrep `p/python`, `r/javascript.lang.security` (regex DoS, missing timeout); Checkov for missing resource limits; Hadolint n/a. A scanner hit is a lead, not a finding.

**Manual checks:** Check limits on body/upload size, page size, concurrency, timeouts, rate limits and quotas per client.

**Rolls up to:** SEC-07, PERF-05, PERF-10, PERF-09, INFRA-12
