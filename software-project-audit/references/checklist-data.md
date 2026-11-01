# D05 Data architecture and integrity — checklist

Questions: see methodology.md §4 D05. This file says how to answer them.

Start from inventory `migrations_dirs` and the ORM in use (Django ORM, SQLAlchemy/Alembic, Prisma, TypeORM, Drizzle, Sequelize, Mongoose). The test run uses whatever database the developer started, so data behavior is still established by reading models, migrations and transaction code; database tests that failed are evidence (`verified_fail` for TEST-08), never a pass. Scanners give almost no leads here.

### DATA-01
**How to check (Python):** Django `models.py`: `unique=True`, `UniqueConstraint`, `CheckConstraint`, `on_delete`, `null=True` on fields that are required by business rules; SQLAlchemy `nullable`, `UniqueConstraint`, `ForeignKey`. Uniqueness enforced only in Python (`if Model.objects.filter(...).exists()`) races.
**How to check (JS/TS):** Prisma `@unique`, `@@unique`, relations with `onDelete`; TypeORM `@Unique`, `@Column({ nullable })`; Mongoose `unique: true` (an index, not validation) and missing refs.
**Evidence to cite:** Model file:line of the missing or weak constraint and the business rule it should enforce.
**Scanner leads:** none — manual.
**Common false positives:** Constraints defined in raw SQL migrations rather than models; check migrations before claiming absence.

### DATA-02
**How to check (Python):** Django `*/migrations/0*.py` ordered and committed; Alembic `versions/` with a linear `down_revision` chain; how migrations run at deploy (entrypoint, release phase, CI job).
**How to check (JS/TS):** `prisma/migrations/*/migration.sql` plus `migrate deploy` (not `db push`) in deploy; TypeORM/Knex/Drizzle migration folders and the deploy command.
**Evidence to cite:** Migration folder, the deploy command file:line, and any gap (`db push`, manual SQL in docs).
**Scanner leads:** none — manual.
**Common false positives:** Squashed migrations are fine; managed platforms that run migrations from a documented release command.

### DATA-03
**How to check (Python):** `transaction.atomic`, `select_for_update`, `F()` expressions vs read-modify-write (`obj.count += 1; obj.save()`); SQLAlchemy `with session.begin()`, `with_for_update()`; Celery task retries re-running non-idempotent writes.
**How to check (JS/TS):** `prisma.$transaction`, optimistic concurrency (`version` column, `updateMany` with a where on version), `findOne` then `save` races, Mongo updates without `$inc`.
**Evidence to cite:** The read-modify-write or multi-step write file:line and the concurrent path (two requests, a retry) that corrupts it.
**Scanner leads:** none — manual.
**Common false positives:** Single-writer flows (one worker, serialized queue) where races cannot occur; document that assumption.

### DATA-04
**How to check (Python):** Payment/webhook handlers: idempotency key stored with a unique constraint, event ID dedupe (`stripe` `event.id`), `get_or_create` race handling, Celery `acks_late` combined with non-idempotent tasks.
**How to check (JS/TS):** Same in webhook route handlers; `Idempotency-Key` headers to Stripe; queue consumers (BullMQ, SQS) that process a message twice on retry.
**Evidence to cite:** Handler file:line, the dedupe mechanism (or its absence), and the duplicate-delivery consequence.
**Scanner leads:** none — manual.
**Common false positives:** Natural idempotency (upsert by external ID with a unique constraint).

### DATA-05
**How to check (Python):** Tenant-scoped managers (`objects.for_tenant`), `django-tenants` schemas, SQLAlchemy queries without `tenant_id` filter, raw SQL in reports and exports, Postgres RLS policies in migrations and the role the app connects as (RLS is bypassed by table owners and `BYPASSRLS`).
**How to check (JS/TS):** Prisma middleware/extensions adding `orgId`, Supabase RLS policies in `supabase/migrations`, use of the `service_role` key (bypasses RLS) in server code reachable by users.
**Evidence to cite:** Query file:line lacking the tenant filter, or the policy SQL file:line and the connecting role.
**Scanner leads:** none — manual (pairs with SEC-02).
**Common false positives:** Admin/reporting code that is meant to be cross-tenant behind staff-only auth.

### DATA-06
**How to check (Python):** Filters and ordering on unindexed columns (`db_index`, `Meta.indexes`, Alembic `create_index`), `.all()` without pagination, DRF without `DEFAULT_PAGINATION_CLASS`, offset pagination on huge tables, tables that only grow (logs, events) with no retention.
**How to check (JS/TS):** Prisma `findMany` without `take`, `@@index`, Mongo queries without matching indexes, endpoints returning entire collections.
**Evidence to cite:** Query file:line, the filter columns, and the index (or migration) that exists or not.
**Scanner leads:** none — manual.
**Common false positives:** Small reference tables; primary-key and unique columns are already indexed.

### DATA-07
**How to check (Python):** IaC (`backup_retention_period`, `point_in_time_recovery`), runbooks, scripts that run `pg_dump`, documented restore tests.
**How to check (JS/TS):** Same; managed-DB settings in Terraform/Pulumi/`supabase` config.
**Evidence to cite:** IaC or doc file:line; state plainly that a restore test cannot be verified from the repository.
**Scanner leads:** Checkov backup/retention checks on IaC (`CKV_AWS_*` for RDS, DynamoDB PITR).
**Common false positives:** Platform defaults (many managed DBs back up by default) — record as `needs_verification`, not absent.

### DATA-08
**How to check (Python):** Event/message payload schemas (Pydantic, JSON Schema, Avro), version fields, consumers tolerant of unknown fields; webhook payload parsing that crashes on new fields.
**How to check (JS/TS):** Zod schemas for incoming events, `strict()` rejecting additive changes, TypeScript types used as if they were runtime validation.
**Evidence to cite:** Producer and consumer file:line and the compatibility gap.
**Scanner leads:** none — manual.
**Common false positives:** Internal events with producer and consumer deployed atomically together.

### DATA-09
**How to check (Python):** Read the latest migrations: `RemoveField`/`DeleteModel`/`AlterField` to non-null without default, renames, `RunPython` backfills in the same migration as schema changes, index creation without `AddIndexConcurrently` on Postgres.
**How to check (JS/TS):** Prisma migration SQL with `DROP COLUMN`, `ALTER COLUMN ... SET NOT NULL`, renames; TypeORM migrations doing data updates inline.
**Evidence to cite:** Migration file:line and the deploy order that would break running code.
**Scanner leads:** none — manual.
**Common false positives:** Small tables, apps with planned downtime windows, migrations on tables created in the same release.

### DATA-10
**How to check (Python):** Django: model fields that do not appear in any migration (a missing `makemigrations`), migrations edited after commit (`git log --follow` on a migration file showing later changes). Alembic: several heads (`down_revision` values reused), `Base.metadata.create_all()` in app startup.
**How to check (JS/TS):** Prisma `schema.prisma` changes without a matching migration folder; TypeORM `synchronize: true` outside tests; Sequelize `sync({ alter: true })`.
**Evidence to cite:** Model file:line versus migration file:line, or the `create_all`/`synchronize` call site.
**Scanner leads:** none — manual.
**Common false positives:** `create_all` used only in tests or a local dev script.

### DATA-11
**How to check (Python):** A DB write followed by `send_mail`, `celery_task.delay()`, `stripe.*` call or webhook POST inside or after `transaction.atomic` — use of `transaction.on_commit`, an outbox table, or a reconciliation job.
**How to check (JS/TS):** `await db.insert(...)` then `await queue.add(...)` with no outbox; payment API called before the order is committed; `$transaction` wrapping external calls.
**Evidence to cite:** The two operations' file:line and the failure window between them.
**Scanner leads:** none — manual.
**Common false positives:** Side effects that are naturally retried and idempotent, or reconciled by a scheduled job you can cite.

### DATA-12
**How to check (Python):** SQLAlchemy `sessionmaker` scope (one per request via dependency with `yield`), sessions stored globally, `pool_size`/`max_overflow` vs gunicorn workers × threads; Django `CONN_MAX_AGE` with async; async engines shared across event loops.
**How to check (JS/TS):** Prisma client instantiated per request or per hot-reload (the `globalThis` pattern), `pg.Pool` max vs serverless concurrency, missing pooler (PgBouncer, Prisma Accelerate, Supabase pooler) in serverless.
**Evidence to cite:** Engine/client creation file:line and the worker/concurrency settings.
**Scanner leads:** none — manual.
**Common false positives:** Low-concurrency internal apps; poolers configured at the platform level (check config).

### DATA-13
**How to check (Python):** `is_deleted`/`deleted_at` flags applied inconsistently in queries; `on_delete=CASCADE` deleting audit data; GDPR export/erase endpoints or scripts; files in storage left behind after DB deletion.
**How to check (JS/TS):** Prisma `onDelete: Cascade`, soft-delete middleware, orphaned uploads, account deletion flows.
**Evidence to cite:** Model/relationship file:line and the query that ignores soft-delete or leaves orphans.
**Scanner leads:** none — manual.
**Common false positives:** Systems with no personal data and no erasure obligation — mark the privacy part `not_applicable` with reason.

### DATA-14
**How to check (Python):** Redis/`django.core.cache` keys set on read with no invalidation on write; denormalized counters updated outside transactions; Elasticsearch/Meilisearch sync via signals that fail silently; rebuild commands.
**How to check (JS/TS):** React Query/SWR cache invalidation after mutations, Next.js `revalidatePath`/`revalidateTag` missing after writes, `unstable_cache` keys, CDN caching of authenticated responses.
**Evidence to cite:** Write path file:line that does not invalidate, and the read path that serves stale data.
**Scanner leads:** none — manual.
**Common false positives:** TTL-based caches where staleness is acceptable by requirement.

### DATA-15
**How to check (Python):** Fixture files (`fixtures/*.json`, `*.sql`, `*.csv`, `seed.py`) with realistic emails, names, phone numbers; test settings pointing at shared DB hosts.
**How to check (JS/TS):** `prisma/seed.ts`, `__fixtures__`, recorded HTTP cassettes containing real data or tokens; test `.env` with staging URLs.
**Evidence to cite:** File path and record type only; never reproduce personal data in the evidence text.
**Scanner leads:** Gitleaks (credentials inside dumps); mostly manual.
**Common false positives:** Faker-generated data, `example.com` addresses.
