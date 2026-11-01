# D06 Testing and quality assurance — checklist

Questions: see methodology.md §4 D06. This file says how to answer them.

Primary inputs: `audit/raw/test-results.json` (status, failed_phase, exit codes, pass/fail/skip/error counts, line/branch coverage per package, notes) and the raw output under each result's `raw_dir`; CI workflow files; the test files themselves. Keep the four states apart: tests present / configured / executed (in the audit's confirmed local run) / enforced before merge (CI plus branch protection, which YAML alone cannot prove). Never run tests yourself outside the confirmed `test --run`.

### TEST-01
**How to check (Python):** `tests/`, `test_*.py`, `*_test.py`, `conftest.py`, `pytest.ini`/`[tool.pytest.ini_options]`, `tox.ini`, `noxfile.py`; Django `tests.py` per app; group by unit / integration (DB, HTTP) / E2E.
**How to check (JS/TS):** `*.test.ts(x)`, `*.spec.ts`, `__tests__/`, `vitest.config.*`, `jest.config.*`, `playwright.config.*`, `cypress/`; map tests to the modules they import.
**Evidence to cite:** Suite list with paths and counts, and the critical modules with no test importing them.
**Scanner leads:** none — manual (test-results.json gives executed counts).
**Common false positives:** Example or template tests left from scaffolding (`App.test.tsx` "renders learn react link").

### TEST-02
**How to check (Python):** Read sample tests in critical areas: do they call the function/endpoint and assert outputs and state, or only `assert mock.called`, `assert "route" in urls`, `import module`?
**How to check (JS/TS):** Snapshot-only tests, `expect(fn).toHaveBeenCalled()` without result checks, tests asserting a component renders without asserting behavior.
**Evidence to cite:** Test file:line examples of hollow assertions next to the behavior they leave untested.
**Scanner leads:** none — manual.
**Common false positives:** Interaction tests where the call itself is the behavior (e.g. "sends exactly one email").

### TEST-03
**How to check (Python):** For each traced critical workflow, search tests for its handler/service names; look for 403/404 assertions on other users' objects, error branches, retry and duplicate-event cases.
**How to check (JS/TS):** Same; supertest/`fetch` against route handlers asserting 401/403; tests of state machines and failure paths.
**Evidence to cite:** Workflow → test file:line mapping, and the negative cases that are missing.
**Scanner leads:** none — manual.
**Common false positives:** Authorization tested centrally once (middleware test) when every route provably uses that middleware.

### TEST-04
**How to check (Python):** `pytest` marks for integration, `TestCase` with DB, `testcontainers`, `pytest-django` `db` fixture, contract tests (schemathesis, pact), RLS tests run as the app role.
**How to check (JS/TS):** Integration suites hitting a real DB (Prisma test DB, testcontainers), Playwright/Cypress E2E, MSW contract fixtures, Pact.
**Evidence to cite:** Suite paths and whether CI runs them (job file:line).
**Scanner leads:** none — manual.
**Common false positives:** Absence of E2E in a backend-only library is not a gap.

### TEST-05
**How to check (Python):** Order-dependent fixtures (module-scoped state mutated), `time.sleep` in tests, `@pytest.mark.flaky`, `pytest-rerunfailures`, retries in CI; compare failures in test-results.json raw output with timing/randomness.
**How to check (JS/TS):** `jest.retryTimes`, Playwright `retries`, arbitrary `waitForTimeout`, shared mutable mocks across tests, missing `vi.restoreAllMocks`.
**Evidence to cite:** File:line of flake-prone constructs and any rerun configuration.
**Scanner leads:** none — manual.
**Common false positives:** Playwright retries on CI as a documented policy with tracking.

### TEST-06
**How to check (Python):** In `.github/workflows/*.yml` (or GitLab/other CI files), find the step that runs `pytest`/`tox`/`nox`/`make test`; check it targets the right paths, is not `|| true` or `continue-on-error: true`, and runs on `pull_request`.
**How to check (JS/TS):** The `npm test`/`pnpm test`/`vitest run` step; scripts in `package.json` it calls (does `test` exist, does it include all workspaces, `--passWithNoTests`).
**Evidence to cite:** Workflow file:line and package.json/Makefile file:line of the invoked command.
**Scanner leads:** actionlint (broken workflow syntax/expressions); zizmor; mostly manual.
**Common false positives:** Tests run in a separate reusable workflow (`workflow_call`) or by an external CI service with config in the repo.

### TEST-07
**How to check (Python):** Per-package line/branch coverage in test-results.json; open the coverage raw data for the critical modules (auth, billing, data writes) rather than the total; `fail_under` in `.coveragerc` / `[tool.coverage.report]`.
**How to check (JS/TS):** Same from the coverage summary; `coverageThreshold` in Jest/Vitest config; `collectCoverageFrom` excluding critical folders.
**Evidence to cite:** Coverage numbers for named critical modules from test-results.json and config file:line.
**Scanner leads:** none — test-results.json.
**Common false positives:** High total coverage driven by trivial code; low coverage in generated or admin code that carries little risk.

### TEST-08
**How to check (Python):** First read `test_run_consent` in context.json. If it is `false`, the developer declined the test run: no tests ran, test-results.json does not exist, and TEST-08 is `not_reviewed` with the reason "developer declined the test run". Otherwise read test-results.json: `status`, `failed_phase` (setup, test), exit codes, counts, coverage, notes, `coverage_tool_suggestion`, and the `skipped` list. The tests ran in the developer's prepared environment, so failures, including a required service being down, are `verified_fail` (the suite is not reliably re-runnable). A package skipped as "project not set up locally", or a declined run, is `not_reviewed` with that reason. Failures caused by the agent's own sandbox are `needs_verification`. A "tests modified the working tree" note is evidence of a re-runnability issue, and a `coverage_tool_suggestion` is a recommendation to relay.
**How to check (JS/TS):** Same.
**Evidence to cite:** test-results.json entry (package, status, counts, coverage) and the relevant raw-output excerpt (no secrets).
**Scanner leads:** none — test-results.json.
**Common false positives:** none — the validator rejects a TEST-08 outcome inconsistent with test-results.json or with a declined test run.

### TEST-09
**How to check (Python):** Pick 2–3 critical functions from the workflow traces; name a concrete mutation (flip `>=` to `>`, drop the owner filter, skip a state check) and read the tests that exercise the function: would any assertion fail?
**How to check (JS/TS):** Same.
**Evidence to cite:** Function file:line, the mutation, and the test file:line that would catch it — or the statement that none would.
**Scanner leads:** none — manual reasoning (do not edit the project to try it).
**Common false positives:** Tests that would catch the mutation indirectly through an integration path; trace it before concluding.

### TEST-10
**How to check (Python):** Tests mocking the ORM/session (`MagicMock()` for `db`), `requests` mocked everywhere with hand-written payloads that differ from the real API, auth dependencies overridden in every test (`app.dependency_overrides`).
**How to check (JS/TS):** `jest.mock('../db')` everywhere, Prisma mocked with `jest-mock-extended` for query logic, MSW handlers returning shapes that do not match the API types.
**Evidence to cite:** Mock file:line and the real contract it diverges from.
**Scanner leads:** none — manual.
**Common false positives:** Mocking third-party paid APIs at the boundary is correct when the mock matches recorded real responses.

### TEST-11
**How to check (Python):** `grep -rn "@pytest.mark.skip\|skipif\|xfail\|@unittest.skip"` in critical tests; commented-out test functions; `--deselect` or `-k "not ..."` in CI.
**How to check (JS/TS):** `grep -rn "\.only(\|\.skip(\|xit(\|xdescribe(\|it\.todo"`; check for a real guard against a committed `.only`: Playwright `forbidOnly: !!process.env.CI`, Mocha `--forbid-only`, Vitest `allowOnly` (false by default when the `CI` env var is set), or ESLint `jest/no-focused-tests` / `vitest/no-focused-tests` enforced in CI. Jest has no built-in guard (`--ci` does not reject `.only`).
**Evidence to cite:** File:line of each skip/only in critical areas and test-results.json skip counts.
**Scanner leads:** none — manual.
**Common false positives:** Platform-specific `skipif(sys.platform == ...)`.

### TEST-12
**How to check (Python):** Tests calling real URLs (`requests.get("https://`), `datetime.now()` without `freezegun`/`time-machine`, `random` without a seed, reading `~/` or absolute paths, `DATABASE_URL` defaulting to a shared host. Network-dependent failures in test-results.json raw output.
**How to check (JS/TS):** Real `fetch` to third parties, `Date.now()` without fake timers, order-dependent `beforeAll` state, `.env.test` pointing at staging.
**Evidence to cite:** Test file:line and the external dependency.
**Scanner leads:** none — manual.
**Common false positives:** Marked, opt-in live tests excluded from the default run.

### TEST-13
**How to check (Python):** Usually `not_applicable` for pure backends; for server-rendered UIs check view tests that exercise templates.
**How to check (JS/TS):** React Testing Library / Vue Test Utils for complex components, one Playwright/Cypress smoke for the main journey (sign-in, checkout), `axe` checks if accessibility is a stated requirement.
**Evidence to cite:** Component/E2E test paths mapped to the critical journeys.
**Scanner leads:** none — manual.
**Common false positives:** Simple presentational components need no tests.

### TEST-14
**How to check (Python):** README/CONTRIBUTING test command; `make test`/`tox`; whether test-results.json needed an inferred command (the plan's notes say how it was found); duration from the run.
**How to check (JS/TS):** `npm test` exists and runs everything; durations; separate slow suites documented.
**Evidence to cite:** Doc file:line of the command, the command the audit actually used, and its duration.
**Scanner leads:** none — test-results.json.
**Common false positives:** Monorepos with per-package commands documented in each package.
