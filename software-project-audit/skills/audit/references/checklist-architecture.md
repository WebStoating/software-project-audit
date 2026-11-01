# D01 Architecture and design — checklist

Questions: see methodology.md §4 D01. This file says how to answer them. Framework entry points are in `references/profile-python.md` and `references/profile-javascript.md`.

Start from `audit/raw/inventory.json` (`packages`, `stacks`, `dockerfiles`, `compose_files`, `k8s_files`, `iac_files`, `docs`). Architecture leads rarely come from scanners; most checks here are `none — manual`. Record an outcome for every check; recommend a different style only when a concrete risk justifies it.

### ARC-01
**How to check (Python):** Read `pyproject.toml` `[project.scripts]`, `manage.py`, `wsgi.py`/`asgi.py`, `app = FastAPI()` / `Flask(__name__)` modules, Celery `app = Celery(...)`, `if __name__ == "__main__":` CLIs, `Procfile`, compose `command:` lines.
**How to check (JS/TS):** Read `package.json` `main`/`bin`/`scripts.start`, `server.ts`/`index.ts` calling `listen(`, Next.js `app/` and `pages/api/`, worker entry files, `serverless.yml`/`vercel.json` functions, workspace packages in `pnpm-workspace.yaml`.
**Evidence to cite:** One line per deployable with its entry file:line, process command (Dockerfile `CMD`, compose service), and the external systems it talks to.
**Scanner leads:** none — manual (inventory.json lists packages, Dockerfiles, compose and IaC files).
**Common false positives:** Example apps, `scripts/` one-offs, test servers and Storybook look like entry points; confirm they are deployed (Dockerfile, compose, CI deploy step) before counting them.

### ARC-02
**How to check (Python):** Map top-level packages; `grep -rn "^from \|^import " <pkg>` and count cross-package imports. Look for "god" modules (`utils.py`, `models.py` with dozens of unrelated classes) imported everywhere. Use `git log --name-only` to see which files change together.
**How to check (JS/TS):** Same with `import ... from '../../..'` depth, `@/` aliases, feature folders importing each other's internals instead of their public `index.ts`.
**Evidence to cite:** The import edges or co-change sets (paths, commit SHAs) that show a change in one area forcing edits in unrelated ones.
**Scanner leads:** none — manual; jscpd `duplication` leads can hint at copy-paste between modules that should share a boundary.
**Common false positives:** Shared `types`/`schemas` packages imported widely are a deliberate contract, not coupling. A small app with one package needs no boundaries.

### ARC-03
**How to check (Python):** In Django views, DRF viewsets, FastAPI routes and Flask views, look for business rules, ORM queries and external calls inline in the handler versus in `services.py`/domain modules. Check whether core logic can be tested without `request`.
**How to check (JS/TS):** Express/Fastify handlers or Next.js route handlers and server actions containing pricing, state transitions or SQL; React components doing data mutation logic instead of hooks/services.
**Evidence to cite:** Handler file:line showing mixed concerns, plus the duplicated rule elsewhere or the test that cannot be written because of it.
**Scanner leads:** Lizard `lizard.ccn` / `lizard.nloc` on handlers point to where mixing is worst.
**Common false positives:** Thin CRUD handlers that delegate to the ORM are fine. Do not demand layers in a small service where the handler is the whole use case.

### ARC-04
**How to check (Python):** Find SDK imports (`stripe`, `boto3`, `twilio`, `openai`, `requests` to vendor URLs). Check whether they are wrapped in one adapter module with timeouts and error mapping, or called from many views and tasks.
**How to check (JS/TS):** Same for `stripe`, `@aws-sdk/*`, `axios`/`fetch` to vendor hosts; check for a `lib/<vendor>.ts` client and typed errors.
**Evidence to cite:** List of call sites per vendor (file:line) and whether failures are caught and mapped.
**Scanner leads:** none — manual (search imports; Semgrep `p/python` / `p/javascript` may flag insecure request options).
**Common false positives:** One direct call site is already isolated. Official SDKs often handle retries internally; read their config before claiming none.

### ARC-05
**How to check (Python):** Look for slow work (emails, PDF generation, vendor calls, large exports) done inside request handlers versus Celery/RQ/`BackgroundTasks`. Check whether FastAPI `BackgroundTasks` is used for work that must survive a crash.
**How to check (JS/TS):** Look for `await sendEmail()` in handlers, unbounded `Promise.all` fan-out, work queued in memory (`setTimeout`, arrays) rather than BullMQ/SQS; serverless functions doing work after the response.
**Evidence to cite:** Handler file:line with the slow or failure-prone call and the latency/failure consequence for the caller.
**Scanner leads:** none — manual.
**Common false positives:** Synchronous calls are correct when the user must see the result (payment confirmation). Low-volume admin endpoints can be slow.

### ARC-06
**How to check (Python):** Identify where identity is established (middleware, `Depends(get_current_user)`, DRF authentication classes) and where privileged clients are created (service-role DB users, admin SDK keys). Trace whether user-controlled data crosses into privileged calls without checks.
**How to check (JS/TS):** Next.js `middleware.ts` matcher, server actions, Supabase/Firebase admin clients (`service_role`, `firebase-admin`) used in request paths; Express routers mounted before/after auth middleware.
**Evidence to cite:** A short data-flow trace: entry file:line → auth point → privileged call file:line.
**Scanner leads:** Semgrep `p/owasp-top-ten` access-control rules; mostly manual.
**Common false positives:** Admin clients used only in migrations, seed scripts or offline jobs are not request-path exposures.

### ARC-07
**How to check (Python):** Compare the deployment footprint (number of services, queues, K8s manifests, IaC) with team size (git authors), traffic hints in docs, and product stage from context.json.
**How to check (JS/TS):** Same; also check for micro-frontends, monorepo tooling (Nx/Turborepo) or GraphQL federation in a small product.
**Evidence to cite:** Manifests and counts (services, workflows, authors) plus the stated goal and stage.
**Scanner leads:** none — manual.
**Common false positives:** Complexity mandated by a customer or regulator is proportionate; ask the user before calling it excessive. Record deliberate choices as `accepted_tradeoff`.

### ARC-08
**How to check (Python):** Read README/`docs/` architecture sections and diagrams; verify each named component, queue, and store exists in code or config, and that code components appear in the docs.
**How to check (JS/TS):** Same; check documented routes against `app/` / router files and documented env vars against `process.env.*` reads.
**Evidence to cite:** Doc file:line of the claim next to the contradicting or confirming code file:line.
**Scanner leads:** none — manual.
**Common false positives:** Docs describing a planned future state clearly labelled as such. Minor naming drift is not material.

### ARC-09
**How to check (Python):** Check whether `domain/`, `core/` or `models` modules import `django.http`, `fastapi`, `flask`, `requests` or infra clients. Find cycles: `grep -rn "^\s\+from \.\|^\s\+import " --include=*.py` shows function-local imports, often hiding a cycle; confirm by reading both modules.
**How to check (JS/TS):** Check core modules importing `next/*`, `express`, or DB clients; find cycles through barrel `index.ts` files re-exporting siblings (symptom: `undefined` at import time, Jest "Cannot access before initialization").
**Evidence to cite:** The two or more import lines (file:line) forming the inverted edge or cycle.
**Scanner leads:** none — manual (the image deliberately ships no import-graph tool; map the graph by reading imports).
**Common false positives:** `TYPE_CHECKING`-guarded imports and `import type` in TS do not create runtime cycles. Django apps importing `django.db` in models are expected.

### ARC-10
**How to check (Python):** For each important table or cache key, find all writers (`.save()`, `.update(`, `session.add`, raw `INSERT/UPDATE`, `redis.set`) across services, workers and scripts.
**How to check (JS/TS):** Same for Prisma/TypeORM/Drizzle/Mongoose writes, `localStorage` vs server state, and multiple services pointing at the same `DATABASE_URL`.
**Evidence to cite:** Writer list per table/key with file:line and whether a lock, version column or owner service coordinates them.
**Scanner leads:** none — manual.
**Common false positives:** Admin and migration writes are expected secondary writers. Append-only event tables tolerate many writers.

### ARC-11
**How to check (Python):** Look for FastAPI-generated OpenAPI, drf-spectacular, `openapi.yaml`, GraphQL schema files, `/v1/` prefixes. Check whether the frontend's types are generated from it or retyped by hand.
**How to check (JS/TS):** Look for `openapi-typescript`, tRPC, GraphQL codegen, shared `packages/types`, Zod schemas shared between client and server; hand-written `interface User` duplicated in frontend and backend.
**Evidence to cite:** Spec/generator config file:line, or the two hand-written definitions that have drifted (field names, optionality).
**Scanner leads:** none — manual.
**Common false positives:** A single-team app with server components and no public API needs no versioning. Internal-only endpoints may reasonably be unversioned.

### ARC-12
**How to check (Python):** Django: `MIDDLEWARE`, DRF `DEFAULT_PERMISSION_CLASSES`/`DEFAULT_AUTHENTICATION_CLASSES`; FastAPI: router-level `dependencies=[Depends(...)]`; Flask: `before_request`. Then sample handlers for per-route re-implementation and for routes that opt out (`permission_classes = []`, `AllowAny`).
**How to check (JS/TS):** Express `app.use(auth)` order versus `app.get` registrations; NestJS global guards/pipes; Next.js `middleware.ts` matcher plus per-route checks in route handlers and server actions (middleware does not cover server actions reliably).
**Evidence to cite:** The central registration file:line and each handler that bypasses or duplicates it.
**Scanner leads:** Semgrep `p/owasp-top-ten` may flag missing CSRF or auth decorators; mostly manual.
**Common false positives:** Public routes (health, login, webhooks with signature checks) legitimately skip user auth. Per-handler checks that call one shared helper are central enough.

### ARC-13
**How to check (Python):** Look for `APScheduler`, `schedule`, Celery beat, `@app.on_event("startup")`/lifespan hooks starting loops, Django `AppConfig.ready()` side effects, gunicorn `--workers` > 1 combined with in-process schedulers.
**How to check (JS/TS):** `node-cron`, `setInterval` in server start, Next.js instrumentation hooks, PM2/cluster mode, multiple replicas in compose/K8s with in-process cron.
**Evidence to cite:** Scheduler start file:line plus the replica/worker setting that multiplies it.
**Scanner leads:** none — manual.
**Common false positives:** Schedulers guarded by a distributed lock or leader election, or deployments that are explicitly single-instance.

### ARC-14
**How to check (Python):** Count vendor SDK imports in domain code (`boto3`, `supabase`, `firebase_admin`, `stripe`), tenancy model (schema-per-tenant, `tenant_id` column), auth provider coupling (Auth0/Cognito claims parsed throughout).
**How to check (JS/TS):** Same for `@supabase/*`, `firebase`, `@clerk/*`, `next-auth` session shape used across components, Vercel-specific APIs (`@vercel/kv`, edge runtime).
**Evidence to cite:** Import counts and representative file:line, plus whether an adapter exists.
**Scanner leads:** none — manual.
**Common false positives:** Deep coupling to a well-chosen platform at an early stage is often a sensible `accepted_tradeoff`; flag only when the exit cost is unknown to the owners or a known move is planned.

### ARC-15
**How to check (Python):** Usually `not_applicable` for pure Python backends; for Django/Jinja templates with HTMX or Alpine, check consistency of the rendering approach.
**How to check (JS/TS):** Next.js: `"use client"` placement, server components importing `server-only` modules, secrets read in client components, data fetching mixed between `fetch` in components, React Query/SWR, and Redux without reason. Vue/Nuxt: `useFetch` vs ad hoc axios. Check `import 'server-only'` guards.
**Evidence to cite:** Component file:line importing server-only code or secrets into a client bundle; the competing data/state libraries in `package.json`.
**Scanner leads:** Semgrep `p/typescript` / `r/javascript.browser.security` for client-side sinks; mostly manual.
**Common false positives:** `NEXT_PUBLIC_*` values intended to be public; two state libraries during a documented migration.
