# D07 CI/CD and developer experience — checklist

Questions: see methodology.md §4 D07. This file says how to answer them.

Inputs: inventory `ci_files`, `github_workflows`, `dockerfiles`, `env_templates`; zizmor, actionlint, Hadolint and Checkov leads; test-results.json (install and test notes are evidence of setup friction). Repository files cannot prove remote settings (branch protection, required checks, environment approvals, secrets scope): record those as `needs_verification` unless the user supplies evidence. zizmor runs offline (no GitHub token), so its online audits did not run.

### CICD-01
**How to check (Python):** Install steps in CI and Dockerfiles use the lockfile (`uv sync --frozen`, `poetry sync` (Poetry 2; `poetry install --sync` on Poetry 1.x) with a committed `poetry.lock`, `pip install -r requirements.lock`/`--require-hashes`); system packages pinned; documented prerequisites in README.
**How to check (JS/TS):** `npm ci`/`pnpm install --frozen-lockfile`/`yarn install --immutable`; `packageManager` + Corepack; build scripts fetching remote assets at build time.
**Evidence to cite:** Install command file:line in CI and Dockerfile; the install outcome in test-results.json.
**Scanner leads:** Hadolint DL3008, DL3013, DL3016; Checkov `CKV_DOCKER_*`.
**Common false positives:** Unpinned apt packages in a throwaway CI step that produces no artifact.

### CICD-02
**How to check (Python):** Workflow steps for `ruff`/`flake8`, `mypy`/`pyright`, `pytest`, build; `if:` conditions or `continue-on-error` that neuter them; triggers (`pull_request` vs only `push` to main).
**How to check (JS/TS):** `lint`, `typecheck` (`tsc --noEmit`), `test`, `build` steps; `next build` with `eslint.ignoreDuringBuilds`/`typescript.ignoreBuildErrors`.
**Evidence to cite:** Workflow file:line for each present check, and the missing ones.
**Scanner leads:** actionlint (expression and syntax errors that make jobs never run); zizmor.
**Common false positives:** Checks run by pre-commit.ci or another hosted CI declared in the repo (`.pre-commit-config.yaml` with ci section).

### CICD-03
**How to check (Python):** Workflow `environment:` keys, per-environment secrets, settings modules per environment, `.env.example` vs deploy config; secrets passed as build args.
**How to check (JS/TS):** Same; Vercel/Netlify env separation via config files; `NEXT_PUBLIC_*` baked at build time per environment.
**Evidence to cite:** Workflow/deploy config file:line showing separation (or a shared secret used by all environments).
**Scanner leads:** zizmor (`secrets-inherit`, `excessive-permissions`); Checkov `CKV_GHA_*`.
**Common false positives:** Environment protection rules configured in the GitHub UI (cannot be seen; `needs_verification`).

### CICD-04
**How to check (Python):** Version source (`pyproject` version, `setuptools-scm`, tags), release workflow on tags, images tagged with commit SHA, documented rollback.
**How to check (JS/TS):** `package.json` version, changesets/semantic-release, image tags, Vercel deployments tied to commits.
**Evidence to cite:** Release workflow file:line and tag/version scheme; rollback doc file:line.
**Scanner leads:** none — manual.
**Common false positives:** Platforms with built-in instant rollback (Vercel, Heroku releases); note as platform capability.

### CICD-05
**How to check (Python):** `CODEOWNERS`, workflow `permissions:`, third-party `uses:` refs; branch protection is remote state.
**How to check (JS/TS):** Same.
**Evidence to cite:** Workflow file:line and `CODEOWNERS` path; state that branch protection was not verifiable from files.
**Scanner leads:** zizmor (`excessive-permissions`, `unpinned-uses`); Checkov `CKV_GHA_*`.
**Common false positives:** Organization-level default read-only token permissions (remote setting; ask the user).

### CICD-06
**How to check (Python):** Where migrations run relative to code rollout (entrypoint `migrate && gunicorn` on every replica races), Celery workers deployed before/after web, release-phase commands.
**How to check (JS/TS):** `prisma migrate deploy` in `postinstall`/`build`/start scripts (runs per instance or at build against prod), job runners vs web deploy order.
**Evidence to cite:** Command file:line and the ordering risk.
**Scanner leads:** none — manual.
**Common false positives:** Single-instance deployments or migrations guarded by advisory locks (Django and Prisma take locks on Postgres).

### CICD-07
**How to check (Python):** README setup path: Python version, env manager, `.env.example`, services (DB, Redis), seed commands. Compare with what the developer's environment needed for the audit's test run.
**How to check (JS/TS):** Same with Node version, package manager, `docker compose up` for services.
**Evidence to cite:** README file:line and the gaps the local test run exposed (also feeds DOC-08).
**Scanner leads:** none — manual.
**Common false positives:** Devcontainer or `compose` files that fully automate setup even if the README is terse.

### CICD-08
**How to check (Python):** Hotfix branch process, ability to deploy a single commit, absence of instructions to edit production by hand (`manage.py shell` in prod runbooks, SSH steps).
**How to check (JS/TS):** Same; scripts that mutate prod data directly.
**Evidence to cite:** Runbook/doc file:line or the deploy workflow that allows targeted releases.
**Scanner leads:** none — manual.
**Common false positives:** Documented, reviewed break-glass procedures.

### CICD-09
**How to check (Python):** Read every workflow: top-level and job `permissions:`, `pull_request_target` checking out PR head (`ref: ${{ github.event.pull_request.head.sha }}`), `${{ github.event.issue.title }}`/`head_ref` interpolated in `run:`, secrets available to fork PRs, `uses:` without a 40-char SHA.
**How to check (JS/TS):** Same.
**Evidence to cite:** Workflow file:line per issue and the zizmor/actionlint lead id.
**Scanner leads:** zizmor (`template-injection`, `dangerous-triggers`, `excessive-permissions`, `unpinned-uses`, `artipacked`, `cache-poisoning`); actionlint (expression injection); Checkov `CKV_GHA_*`.
**Common false positives:** `pull_request_target` workflows that never check out PR code (labelers); expressions over trusted contexts (`github.sha`).

### CICD-10
**How to check (Python):** Does deploy build a new image per environment from source (`docker build` in each deploy job) or promote one digest? Does CI test the same Dockerfile target that ships?
**How to check (JS/TS):** Same; Next.js builds that bake env-specific `NEXT_PUBLIC_*` values force rebuilds per environment (a known drift source).
**Evidence to cite:** Build and deploy job file:line.
**Scanner leads:** none — manual.
**Common false positives:** Platforms that build once per commit and promote (Vercel preview to prod promotion).

### CICD-11
**How to check (Python):** Dockerfile: multi-stage, `FROM ...@sha256:`, `USER` non-root, `uv sync --no-dev`, no `COPY . .` of `.env`, `ARG`s carrying secrets, `.dockerignore` with `.env`, `.git`, `.venv`.
**How to check (JS/TS):** Same with `node_modules`, `npm ci --omit=dev` in the final stage, Next.js standalone output.
**Evidence to cite:** Dockerfile file:line and `.dockerignore` contents (or absence).
**Scanner leads:** Hadolint DL3002 (last user root), DL3006/DL3007, DL3008, DL3013, DL3016, DL3025; Checkov `CKV_DOCKER_2` (healthcheck), `CKV_DOCKER_3` (user) and other `CKV_DOCKER_*`.
**Common false positives:** Dev-only Dockerfiles (`Dockerfile.dev`) used with compose locally.

### CICD-12
**How to check (Python):** `pydantic-settings` `BaseSettings` or explicit checks at startup vs `os.getenv("X")` returning None deep in code; compare every env read (`grep -rn "os.environ\|os.getenv\|env("`) with `.env.example`.
**How to check (JS/TS):** `env.ts` with Zod/`@t3-oss/env` parsed at boot vs `process.env.X!`; compare reads with `.env.example`.
**Evidence to cite:** Read sites missing from the template (names only) and the startup validation file:line.
**Scanner leads:** none — manual.
**Common false positives:** Variables provided by the platform (`PORT`, `VERCEL_URL`, `DYNO`).

### CICD-13
**How to check (Python):** SQLite in dev/test settings vs Postgres in prod (`DATABASES` per settings file), compose service versions vs IaC versions, Python versions (see DEP-11).
**How to check (JS/TS):** Prisma `provider` switched by env, in-memory Mongo for tests, compose Postgres version vs managed DB version.
**Evidence to cite:** Settings/compose/IaC file:line for each environment.
**Scanner leads:** none — manual.
**Common false positives:** SQLite for pure unit tests while integration tests use the real engine.

### CICD-14
**How to check (Python):** Post-deploy step hitting `/health`, smoke tests in the deploy workflow, health-check grace in IaC/K8s, documented rollback criteria.
**How to check (JS/TS):** Same; Vercel checks, Playwright smoke against preview URLs.
**Evidence to cite:** Workflow or IaC file:line; rollback doc file:line.
**Scanner leads:** none — manual.
**Common false positives:** Platform-managed health gating (K8s readiness with rolling updates, ECS deployment circuit breaker) declared in IaC.
