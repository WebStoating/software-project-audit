# D10 Performance, scalability, and resilience — checklist

Questions: see methodology.md §4 D10. This file says how to answer them.

The Standard Audit runs no load tests or profilers, so findings here come from code and configuration. Do not predict failure at an invented user count or size infrastructure without workload evidence; state assumptions and make measurement the verification step. Lizard leads show where complexity concentrates, not where time is spent.

### PERF-01
**How to check (Python):** N+1: loops over querysets touching relations without `select_related`/`prefetch_related`; SQLAlchemy lazy loads in loops (`lazy="select"`) without `selectinload`; DRF serializers with nested relations; sync vendor calls inside loops; `sorted`/nested loops over large collections in request paths.
**How to check (JS/TS):** `for (...) await prisma.x.findUnique()` instead of `findMany({ where: { id: { in } } })`; GraphQL resolvers without DataLoader; `await` in loops where batching is possible; unbounded `Promise.all` fan-out to vendors.
**Evidence to cite:** Loop file:line, the query or call inside it, and the expected cardinality.
**Scanner leads:** Lizard `lizard.ccn` / `lizard.nloc` for hot functions; mostly manual.
**Common false positives:** Loops over small fixed sets; admin-only pages; ORMs with explicit eager loading configured on the relation.

### PERF-02
**How to check (Python):** Per dependency: timeout (see PERF-09), retry (`tenacity`, `urllib3.Retry`, Celery `autoretry_for`) with backoff and jitter, retry only on idempotent operations, circuit breaker (`pybreaker`) where a slow dependency could exhaust workers.
**How to check (JS/TS):** `axios-retry`, `p-retry`, `got` retries, `opossum` circuit breakers, BullMQ backoff settings.
**Evidence to cite:** Client config file:line per dependency and the missing behavior.
**Scanner leads:** none — manual.
**Common false positives:** Official SDKs with built-in retries/backoff (Stripe, AWS SDK) — check their config before claiming none.

### PERF-03
**How to check (Python):** Celery: `time_limit`/`soft_time_limit`, `acks_late` + idempotency, `max_retries`, `rate_limit`, prefetch multiplier for long tasks; RQ job timeouts; tasks that enqueue themselves without bounds.
**How to check (JS/TS):** BullMQ `attempts`, `backoff`, job timeouts, concurrency; SQS visibility timeout vs processing time; Lambda timeouts.
**Evidence to cite:** Task definition file:line and the unbounded or non-idempotent aspect.
**Scanner leads:** none — manual.
**Common false positives:** Short tasks where defaults are adequate.

### PERF-04
**How to check (Python):** Hot read paths without caching (`cache_page`, `functools.lru_cache` misuse on per-user data), bulk ops (`bulk_create`, `executemany`) vs per-row saves, pagination on list endpoints, indexes for filters (pairs with DATA-06).
**How to check (JS/TS):** `createMany`, batched writes, React Query/SWR caching, Next.js `fetch` cache/revalidate settings, CDN caching headers on public assets.
**Evidence to cite:** Endpoint/query file:line and why the workload makes it matter.
**Scanner leads:** none — manual.
**Common false positives:** Low-traffic endpoints; caches that would add invalidation risk with little gain.

### PERF-05
**How to check (Python):** `request.body`/`await request.body()` reading whole uploads, `DATA_UPLOAD_MAX_MEMORY_SIZE`/`FILE_UPLOAD_MAX_MEMORY_SIZE`, `.read()` of uploaded files, unbounded `asyncio.gather`, pandas loads of user files, gunicorn `--timeout`.
**How to check (JS/TS):** `express.json()` without `limit`, `multer` without `limits`, buffering streams into memory, `Promise.all(items.map(...))` over user-sized arrays, `JSON.parse` of large bodies.
**Evidence to cite:** Handler file:line and the missing bound.
**Scanner leads:** Semgrep `p/cwe-top-25` (CWE-770 resource allocation); mostly manual.
**Common false positives:** Limits enforced by a reverse proxy (`client_max_body_size`, ALB limits) declared in config.

### PERF-06
**How to check (Python):** Compare declared topology (single DB, single worker, one Redis) with stated RTO/RPO or availability requirements; recovery mechanisms (retries on reconnect, worker restart policies).
**How to check (JS/TS):** Same.
**Evidence to cite:** IaC/compose file:line and the stated target (or "no stated target").
**Scanner leads:** none — manual (pairs with INFRA-06).
**Common false positives:** No stated targets: record as information, not a defect.

### PERF-07
**How to check (Python):** Vendor calls per request (LLM, maps, email, SMS), vendor rate limits and quotas handled (429 handling, backoff), cost per call multiplied by retries or loops.
**How to check (JS/TS):** Same; client-side calls to paid APIs that users can trigger repeatedly.
**Evidence to cite:** Call site file:line, trigger frequency, and 429/limit handling.
**Scanner leads:** none — manual.
**Common false positives:** Calls cached or batched upstream.

### PERF-08
**How to check (Python):** README/docs claims ("handles 10k rps", "scales horizontally") and any benchmark scripts, load-test configs or results committed.
**How to check (JS/TS):** Same; Lighthouse CI budgets, bundle analysis reports.
**Evidence to cite:** Claim file:line and the supporting measurement or its absence.
**Scanner leads:** none — manual.
**Common false positives:** Claims explicitly labelled as goals.

### PERF-09
**How to check (Python):** `grep -rn "requests\.\(get\|post\|put\|delete\|request\)(" --include=*.py` without `timeout=`; `httpx` clients (default 5 s, check overrides to `None`); `urllib.request.urlopen` without timeout; `requests.Session` created per call (no reuse); DB `connect_timeout`/statement timeout.
**How to check (JS/TS):** `fetch` without `AbortSignal.timeout()`; `axios` without `timeout` (default none); `got`/`undici` config; new agents per request (no keep-alive).
**Evidence to cite:** Call site file:line per missing timeout and the request path it blocks.
**Scanner leads:** Bandit B113 (requests without timeout); Semgrep `p/python` (requests timeout rules).
**Common false positives:** Calls wrapped by a client factory that sets timeouts centrally — read the factory.

### PERF-10
**How to check (Python):** `limit`/`page_size` from query params without max (`max_page_size` in DRF pagination), bulk export endpoints without async jobs, `re` patterns with nested quantifiers on user input, GraphQL (Strawberry/Graphene) without depth/complexity limits.
**How to check (JS/TS):** Same; Apollo/Yoga without depth limit or cost analysis, `new RegExp(userInput)`, regexes like `(a+)+$`.
**Evidence to cite:** Parameter or regex file:line and the amplification factor.
**Scanner leads:** Semgrep `p/javascript`, `r/javascript.lang.security` (ReDoS, non-literal RegExp), `p/python`.
**Common false positives:** Regexes applied only to trusted or length-limited input.

### PERF-11
**How to check (Python):** gunicorn/uvicorn config (`workers`, `graceful_timeout`, `--timeout`), Celery `worker_concurrency`, SIGTERM handling in custom workers, FastAPI lifespan shutdown closing clients.
**How to check (JS/TS):** `process.on('SIGTERM')` with `server.close()`, BullMQ `worker.close()`, PM2/cluster settings, container `STOPSIGNAL` and stop grace periods.
**Evidence to cite:** Config/entrypoint file:line; note if the shell-form `CMD` prevents signal delivery.
**Scanner leads:** Hadolint DL3025 (JSON-form `CMD` for signal handling).
**Common false positives:** Platforms that drain connections at the load balancer; stateless request handlers with short timeouts.

### PERF-12
**How to check (Python):** Usually `not_applicable` for backend-only projects.
**How to check (JS/TS):** Heavy client imports (`moment`, full `lodash`, chart libraries) in critical routes, missing `next/dynamic`/`React.lazy`, `<img>` instead of `next/image` for large media, client-side fetch waterfalls, context providers re-rendering whole trees.
**Evidence to cite:** Import or component file:line and the critical journey affected.
**Scanner leads:** none — manual.
**Common false positives:** Internal tools where load time is not a requirement.
