# D02 Code quality and maintainability — checklist

Questions: see methodology.md §4 D02. This file says how to answer them.

Metrics (Lizard `lizard.ccn` above 15, `lizard.nloc` above 100, jscpd `duplication`) are prioritization leads, never findings on their own. A finding needs a concrete change or correctness risk in a path that matters. Ruff runs with the project's config if one exists, otherwise with Ruff defaults (pyflakes plus a few pycodestyle errors): the absence of a Ruff rule family in `leads.json` usually means it was not enabled, not that the code is clean.

### CODE-01
**How to check (Python):** Look for non-idiomatic patterns with real cost: manual resource handling instead of `with`, Django querysets evaluated in loops, `datetime.now()` without tz, string-built paths instead of `pathlib`, Flask global `g` misuse, FastAPI sync `def` routes doing I/O mixed with `async def`.
**How to check (JS/TS):** Callback/promise mixing, `var`, `==` on mixed types, React hooks called conditionally, effects missing dependencies, mutating props/state directly, Express error handlers with the wrong arity.
**Evidence to cite:** Representative file:line instances and why the idiom breach causes bugs or slows change.
**Scanner leads:** Ruff (whatever families the project enables, e.g. `B`, `SIM`, `UP`); Semgrep `p/python`, `p/javascript`, `p/typescript` correctness rules.
**Common false positives:** Style preferences with no behavioral or maintenance cost; generated code; vendored code.

### CODE-02
**How to check (Python):** Open the top Lizard leads in critical modules; read whether the branching encodes business rules that are hard to test. Look for module-level mutable state (`_cache = {}`) and `utils.py` grab-bags.
**How to check (JS/TS):** Same; also giant React components (state + fetch + render), Redux reducers with deep switch logic, shared `helpers.ts` imported by everything.
**Evidence to cite:** Function file:line with CCN/NLOC from the lead id, plus the concrete risk (recent bug fix commits, duplicated rule drift, untestable branch).
**Scanner leads:** Lizard (`lizard.ccn`, `lizard.nloc`), jscpd (`duplication`).
**Common false positives:** Parsers, state machines and generated switch tables are legitimately branchy. Duplication in tests and migrations is usually fine.

### CODE-03
**How to check (Python):** Check function signatures and return types on boundary code, `Optional` handling (`.get()` result used without a None check), Pydantic/dataclass models versus bare dicts, `TypedDict` for JSON shapes.
**How to check (JS/TS):** Check `strictNullChecks`, non-null assertions (`!`), optional chaining hiding missing data, `JSON.parse` results typed by cast, API response types not validated at runtime.
**Evidence to cite:** The unchecked null/error path file:line and the caller that would crash or misbehave.
**Scanner leads:** Ruff if the project enables type-related rules; Semgrep `p/typescript`; mostly manual.
**Common false positives:** Internal helpers whose callers guarantee non-null; framework-provided validated objects.

### CODE-04
**How to check (Python):** `grep -rn "except:\|except Exception\|except BaseException" --include=*.py`; read each in critical paths: does it log and re-raise, map to a domain error, or `pass`? Check Django/DRF/FastAPI exception handlers returning `str(e)` or tracebacks to clients.
**How to check (JS/TS):** `catch (e) {}`, `.catch(() => {})`, `catch` that returns 200, Express error middleware sending `err.stack` or `err.message` from DB drivers; Next.js `error.tsx` showing raw messages.
**Evidence to cite:** The catch site file:line, what is lost or leaked, and the affected workflow.
**Scanner leads:** Bandit B110 (try/except/pass), B112 (try/except/continue); Ruff `E722`, `BLE001`, `S110` when enabled; Semgrep `p/python` / `p/javascript`.
**Common false positives:** Best-effort cleanup (closing a socket, deleting a temp file) and optional telemetry calls may swallow deliberately; check for a comment or log.

### CODE-05
**How to check (Python):** Files/sockets/DB sessions opened without `with`; `threading` with shared mutable state; `asyncio.create_task` without keeping a reference; cancellation ignored in `except asyncio.CancelledError: pass`; `ThreadPoolExecutor` never shut down.
**How to check (JS/TS):** Streams without error handlers, DB clients created per request and never closed, event listeners added without removal, `AbortController` not wired to fetches, React effects without cleanup.
**Evidence to cite:** The acquire site file:line and the missing release or cancel path.
**Scanner leads:** Ruff `SIM115`, `ASYNC` family when enabled; Semgrep `p/python`; mostly manual.
**Common false positives:** Process-lifetime singletons (one pool for the app) are intended to live forever.

### CODE-06
**How to check (Python):** Look for settings modules (`settings/base.py`, `config.py`, `pydantic-settings` `BaseSettings`) versus `os.environ` reads scattered across modules; hardcoded `https://` hosts, ports and bucket names in code.
**How to check (JS/TS):** `process.env.X` reads spread through components and handlers instead of one validated `env.ts` (e.g. `@t3-oss/env`, Zod); hardcoded API base URLs; `import.meta.env` usage.
**Evidence to cite:** The hardcoded value or scattered read file:line and the environment it breaks.
**Scanner leads:** Gitleaks (secrets, always redacted), Bandit B105/B106/B107 (hardcoded passwords); Semgrep `p/python`, `p/javascript`.
**Common false positives:** Public URLs of third-party APIs, localhost defaults in dev-only config, test fixtures.

### CODE-07
**How to check (Python):** Read the public functions of main modules: consistent naming, clear responsibilities, `__all__` or private `_` prefixes, circular "manager/helper/handler" names that hide purpose.
**How to check (JS/TS):** Exported API of packages/modules, mixed default/named export conventions, inconsistent file naming (`userService.ts` vs `user-service.ts`) that hides duplicates.
**Evidence to cite:** Examples that caused or would cause a wrong call (two functions with near-identical names and different semantics).
**Scanner leads:** none — manual.
**Common false positives:** Pure naming taste. Only report when it creates measurable confusion or duplicated implementations.

### CODE-08
**How to check (Python):** `grep -rn "eval(\|exec(\|getattr(.*request\|importlib.import_module\|__import__\|# pragma: no cover\|NotImplementedError\|raise NotImplemented"`; stub returns (`return True  # TODO`), `typing.cast` on external data, monkeypatching in production code.
**How to check (JS/TS):** `as any`, `as unknown as`, `eval`, `new Function`, `require(variable)`, `// @ts-expect-error`, functions returning hardcoded mock data, `if (process.env.NODE_ENV === 'test')` branches in production code.
**Evidence to cite:** The shortcut file:line and proof it is on a live path (route registration, caller).
**Scanner leads:** Bandit B307, B102; Semgrep `p/python`, `p/javascript`, `r/javascript.lang.security`; Ruff `F401`/`F841` for dead code.
**Common false positives:** Plugin loaders with an allowlist; dead code that is genuinely unreachable and only a cleanup item.

### CODE-09
**How to check (Python):** Read `mypy.ini`/`pyproject [tool.mypy]`/`pyrightconfig.json`: is it run in CI (workflow step), with `strict` or `disallow_untyped_defs` on critical packages? Count `grep -rn "# type: ignore" | wc -l` and `Any` in signatures.
**How to check (JS/TS):** `tsconfig.json` `strict`, `noImplicitAny`, `skipLibCheck` (fine), `allowJs` with untyped JS; count `grep -rn ": any\|as any\|@ts-ignore\|@ts-nocheck\|as unknown as"`; check `tsc --noEmit` runs in CI or the build.
**Evidence to cite:** Config file:line, CI step (or its absence), and counts in critical folders.
**Scanner leads:** none — manual (counts by search).
**Common false positives:** Next.js builds type-check by default unless `typescript.ignoreBuildErrors` is set. `any` in test files is low risk.

### CODE-10
**How to check (Python):** FastAPI: body params typed as Pydantic models versus `request: Request` + `await request.json()`; Django: DRF serializers/forms versus `request.POST.get` used directly; Flask: `request.json["x"]` passed to services.
**How to check (JS/TS):** Zod/Yup/class-validator/`fastify` schemas at the route, versus `req.body` destructured and passed down; Next.js server actions trusting `FormData` without parsing.
**Evidence to cite:** Entry file:line where raw input enters and the deepest file:line where it is used unvalidated.
**Scanner leads:** Semgrep `p/owasp-top-ten` taint rules may show flows; mostly manual.
**Common false positives:** Validation done by a global middleware or a framework decorator; check before claiming absence.

### CODE-11
**How to check (Python):** `datetime.now()`/`utcnow()` (naive), `USE_TZ = False` in Django, `float` for prices, `round()` on money, `Decimal(float)`, `uuid1`, IDs from `random`, `open()` without `encoding=`.
**How to check (JS/TS):** `new Date()` string parsing, `toFixed` on money, amounts as JS numbers in floating point, `Date.now()` as an ID, moment/dayjs without tz plugins, timestamps stored as local strings.
**Evidence to cite:** File:line where the value is created or stored, and the workflow (billing, scheduling) it corrupts.
**Scanner leads:** Ruff `DTZ` family when enabled; Bandit B311 (random); mostly manual.
**Common false positives:** Display-only formatting; integer cents in JS numbers is correct; naive datetimes in a system that is documented as single-timezone.

### CODE-12
**How to check (Python):** In `async def` handlers, find `requests.`, `time.sleep`, sync DB drivers (`psycopg2`, sync SQLAlchemy session), file I/O, CPU-heavy work; `asyncio.create_task` without stored reference; coroutines called without `await`.
**How to check (JS/TS):** `fs.readFileSync`/`execSync` in request handlers, missing `await` on promises (lost errors), `forEach(async ...)`, no `process.on('unhandledRejection')` policy, floating promises in event handlers.
**Evidence to cite:** Handler file:line with the blocking or unawaited call.
**Scanner leads:** Ruff `ASYNC` family when enabled; Semgrep `p/python`, `p/typescript`; mostly manual.
**Common false positives:** Sync code in `def` (not `async def`) FastAPI routes runs in a threadpool and is fine. Sync `fs` at startup is fine.

### CODE-13
**How to check (Python):** Ruff/visual check for mutable defaults (`def f(x=[])`), module-level clients storing user data, globals mutated in views, import-time DB or network calls, `threading.local` misuse under async.
**How to check (JS/TS):** Module-scope variables mutated per request in Next.js/Express (leak across users in SSR and warm serverless instances), singletons caching user-specific data, Redux store created at module scope on the server.
**Evidence to cite:** The shared state file:line and the per-request write that leaks.
**Scanner leads:** Ruff `B006`, `B008`, `PLW0603` when enabled; Semgrep `p/python`; mostly manual.
**Common false positives:** Module-level read-only config, compiled regexes, connection pools.

### CODE-14
**How to check (Python):** `pyproject [tool.ruff]`/`.flake8`/`setup.cfg`; CI step that runs it; `grep -rn "# noqa$\|# noqa:\|ruff: noqa\|# type: ignore"`; `exclude`/`extend-exclude` covering source folders.
**How to check (JS/TS):** `eslint.config.*`/`.eslintrc*`, `.prettierrc`, `lint` script used in CI, `/* eslint-disable */` at file top, `.eslintignore` excluding `src/`, `next lint` disabled via `eslint.ignoreDuringBuilds`.
**Evidence to cite:** Config and CI file:line, plus counts of blanket suppressions in critical folders.
**Scanner leads:** Ruff output (with project config) shows what currently fails; mostly manual.
**Common false positives:** Targeted suppressions with a reason comment are healthy. Generated folders excluded from lint are expected.

### CODE-15
**How to check (Python):** `grep -rn "TODO\|FIXME\|HACK\|XXX" --include=*.py` restricted to critical modules (auth, billing, data writes); flag libraries (LaunchDarkly, Unleash, custom `FEATURE_*` settings) with flags older than months per `git log -S`.
**How to check (JS/TS):** Same across `src/`, `app/`; feature-flag checks in components; near-duplicate files (`*-old.ts`, `*.v2.tsx`).
**Evidence to cite:** Markers in critical paths with file:line and whether they reference an issue ID.
**Scanner leads:** jscpd (`duplication`) for copy-pasted variants; Ruff `FIX`/`TD` families when enabled.
**Common false positives:** TODOs in tests, docs or vendored code; markers referencing a tracked issue.
