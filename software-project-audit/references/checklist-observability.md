# D09 Observability and operations — checklist

Questions: see methodology.md §4 D09. This file says how to answer them.

Evidence ladder: SDK installed ≠ telemetry emitted ≠ dashboard configured ≠ alert working ≠ someone responding. The repository usually proves only the first two; dashboards and alerts count only when declared as code (Terraform `datadog_monitor`, Grafana JSON, `PrometheusRule`, Sentry alert config). Missing instrumentation in one handler does not prove framework or platform instrumentation is absent: check auto-instrumentation and platform logging first. No scanner covers this domain.

### OBS-01
**How to check (Python):** `LOGGING` dict in Django settings, `logging.basicConfig`, `structlog`/`python-json-logger`, `loguru`; log calls at state changes and failures in critical workflows (`logger.exception` in except blocks).
**How to check (JS/TS):** `pino`/`winston`/`bunyan` setup, `console.*` usage, Next.js `instrumentation.ts`, log levels per environment.
**Evidence to cite:** Logger setup file:line and examples in critical paths (or the silent failure branch).
**Scanner leads:** none — manual.
**Common false positives:** Platform request logs (Vercel, Cloud Run, Heroku router) cover access logging; don't demand app-level request logs.

### OBS-02
**How to check (Python):** Request-ID middleware (`django-guid`, `asgi-correlation-id`), OpenTelemetry instrumentation (`opentelemetry-instrumentation-django/fastapi/requests/celery`), propagation of headers to outbound calls and into Celery task headers.
**How to check (JS/TS):** `@opentelemetry/auto-instrumentations-node`, `AsyncLocalStorage` request context, `x-request-id` forwarding in fetch wrappers, Next.js `@vercel/otel`.
**Evidence to cite:** Middleware/instrumentation file:line and a boundary where the ID is dropped.
**Scanner leads:** none — manual.
**Common false positives:** Single-process apps with no cross-service hops.

### OBS-03
**How to check (Python):** `prometheus_client`/`django-prometheus`, StatsD, OTel metrics, Celery queue metrics; metrics for dependency latency and errors.
**How to check (JS/TS):** `prom-client`, OTel metrics, APM SDKs (Datadog `dd-trace`, New Relic) with auto-metrics.
**Evidence to cite:** Metric definitions file:line and the important dependency or queue without one.
**Scanner leads:** none — manual.
**Common false positives:** APM agents that capture latency/throughput automatically once configured.

### OBS-04
**How to check (Python):** For each traced workflow, follow whether one ID or span ties the HTTP handler, the Celery/RQ task, DB calls and vendor calls together.
**How to check (JS/TS):** Same across route handlers, queue consumers (BullMQ jobs carrying context), and third-party calls.
**Evidence to cite:** The workflow trace with each hop's file:line and whether context crosses it.
**Scanner leads:** none — manual.
**Common false positives:** Synchronous single-service flows already covered by one request log.

### OBS-05
**How to check (Python):** Explicit events/logs/metrics for business failures (payment declined, webhook rejected, booking not created) beyond exceptions; reconciliation reports.
**How to check (JS/TS):** Same; analytics events used for operational failure signals.
**Evidence to cite:** File:line of the failure branch and what (if anything) is emitted there.
**Scanner leads:** none — manual.
**Common false positives:** Failures surfaced to users and support via a durable status field that ops can query.

### OBS-06
**How to check (Python):** Alert definitions as code, routing (PagerDuty/Opsgenie integrations), runbook links in alert descriptions, `docs/runbooks/`.
**How to check (JS/TS):** Same.
**Evidence to cite:** Alert resource file:line and runbook path; otherwise `needs_verification` (alerts may live in a vendor UI).
**Scanner leads:** none — manual.
**Common false positives:** Absence in the repo is not absence in production; ask the user before calling it a gap.

### OBS-07
**How to check (Python):** `sentry_sdk.init` (DSN from env, `send_default_pii`, `before_send` scrubbing), exceptions swallowed before reaching it (pairs with CODE-04), Celery task failure handlers.
**How to check (JS/TS):** `@sentry/node`/`@sentry/nextjs` setup, Express error middleware forwarding to Sentry, unhandled rejection handlers.
**Evidence to cite:** Init file:line and swallowing sites.
**Scanner leads:** Bandit B110/B112 and Ruff `BLE001` when enabled point to swallowed exceptions.
**Common false positives:** Expected exceptions (validation errors, 404s) filtered out deliberately.

### OBS-08
**How to check (Python):** Log fields carrying emails, tokens, full request bodies; high-cardinality metric labels (user IDs, URLs with IDs); retention settings in IaC (`retention_in_days`).
**How to check (JS/TS):** `pino` redact paths, Sentry `beforeSend`, metric labels from `req.path`.
**Evidence to cite:** File:line of the sensitive field or label and the retention setting.
**Scanner leads:** none — manual (Checkov flags log groups without retention or encryption in IaC).
**Common false positives:** Hashed or tokenized identifiers.

### OBS-09
**How to check (Python):** `/health` vs `/ready` endpoints (does readiness check the DB?), K8s/compose healthchecks pointing at them, Celery worker health.
**How to check (JS/TS):** Same; Next.js route handler for health, Docker `HEALTHCHECK`.
**Evidence to cite:** Endpoint file:line and probe config file:line.
**Scanner leads:** Checkov `CKV_DOCKER_2`, `CKV_K8S_*` probe checks.
**Common false positives:** Liveness that deliberately avoids dependency checks (correct; readiness should check them).

### OBS-10
**How to check (Python):** SLO definitions (docs, `slo.yaml`, Terraform SLO resources) only if the product has reliability commitments (SLA, contract) per context.json.
**How to check (JS/TS):** Same.
**Evidence to cite:** SLO file:line, or `not_applicable` with "no stated reliability objective".
**Scanner leads:** none — manual.
**Common false positives:** Early-stage products without commitments do not need SLOs.

### OBS-11
**How to check (Python):** Celery `task_failure` signals, `autoretry_for` with `max_retries` and a terminal handler, dead-letter queues, Flower exposure, heartbeat pings (Healthchecks.io, Cronitor, Sentry Crons) for beat/cron jobs.
**How to check (JS/TS):** BullMQ `failed` events and `removeOnFail`, SQS DLQ in IaC, `node-cron` job error handling, Vercel cron monitoring.
**Evidence to cite:** Job definition file:line and the failure visibility mechanism.
**Scanner leads:** none — manual (Checkov may flag SQS queues without DLQ in IaC).
**Common false positives:** Jobs whose failure is self-healing and surfaced by a downstream check you can cite.

### OBS-12
**How to check (Python):** Sentry `release=`, OTel `service.version`, log fields with commit SHA, build args passing `GIT_SHA` into the image.
**How to check (JS/TS):** Same; `@sentry/nextjs` release injection, `VERCEL_GIT_COMMIT_SHA`.
**Evidence to cite:** Init or build file:line.
**Scanner leads:** none — manual.
**Common false positives:** Platforms that tag telemetry with the deployment automatically.

### OBS-13
**How to check (Python):** Usually `not_applicable` for backend-only projects.
**How to check (JS/TS):** `@sentry/react`/`@sentry/nextjs` browser init, source map upload in CI (and not publicly served), `web-vitals`/`reportWebVitals`, Vercel Speed Insights.
**Evidence to cite:** Client init file:line and source-map upload step file:line.
**Scanner leads:** none — manual.
**Common false positives:** Internal admin UIs with low criticality.

### OBS-14
**How to check (Python):** Log level per environment (`LOG_LEVEL` env, DEBUG in prod), request/response body logging middleware, `print(` as the only error path (`grep -rn "print(" --include=*.py` in non-CLI code), stack traces at INFO.
**How to check (JS/TS):** `console.log` as error handling, `morgan('dev')` in production, body-logging middleware, pino level config.
**Evidence to cite:** Config file:line and representative noisy or silent sites.
**Scanner leads:** Ruff `T20` (print) when enabled; mostly manual.
**Common false positives:** CLIs and scripts where printing is the interface.
