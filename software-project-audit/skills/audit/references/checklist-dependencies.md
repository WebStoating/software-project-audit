# D04 Dependencies and software supply chain — checklist

Questions: see methodology.md §4 D04. This file says how to answer them.

OSV-Scanner and Trivy are the advisory sources in the image (pip-audit and npm audit are deliberately excluded). When both report the same package and advisory (or an alias such as the CVE behind a GHSA), `leads.json` holds one lead listing both tools. An advisory lead names a package and version from a manifest or lockfile; it is not a finding until version, applicability, reachability and exposure are checked. If either tool is `failed`/`partial` in `run-ledger.json`, DEP-02 cannot be `reviewed_no_issue`.

### DEP-01
**How to check (Python):** Inventory `packages` lists manifests per package; confirm a lockfile exists for each deployable: `uv.lock`, `poetry.lock`, `Pipfile.lock`, or fully pinned `requirements*.txt` (ideally `pip-compile` output with hashes). `setup.py`/`pyproject` ranges alone are not a lock. Note any committed SBOM (CycloneDX `bom.json`/`*.cdx.json`, SPDX `*.spdx.json`) and whether it matches the lockfile.
**How to check (JS/TS):** `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` at the workspace root; lockfile committed (not in `.gitignore`); every workspace covered; committed CycloneDX/SPDX SBOMs and whether they are current.
**Evidence to cite:** Manifest, lockfile and SBOM paths per package; any deployable with no lock.
**Scanner leads:** OSV-Scanner and Trivy (which manifests and lockfiles each parsed shows in its raw output: OSV `source.path`, Trivy `Results[].Target`).
**Common false positives:** Libraries (published packages) intentionally ship without a lock; check whether the repo is an app or a library.

### DEP-02
**How to check (Python):** For each advisory lead, read the advisory's affected range against the locked version, then search imports of the affected module/function (`grep -rn "import yaml\|from jinja2"`); is it on a request path with untrusted input?
**How to check (JS/TS):** Same; check if the package is only in `devDependencies` or a build tool, whether it ships in the client bundle, and whether the vulnerable API is called.
**Evidence to cite:** Lead id, advisory id (GHSA/CVE/PYSEC), locked version, fixed version, and the reachability trace or the reason it is unreachable.
**Scanner leads:** OSV-Scanner; Trivy (`extra.installed_version`, `extra.fixed_version`, `extra.vuln_id`).
**Common false positives:** Advisories for features not used (e.g. a CLI subcommand), dev-only tooling, transitive packages never loaded at runtime. Note them in the finding's validation statement rather than dropping silently.

### DEP-03
**How to check (Python):** `requires-python`, `.python-version`, Docker base tags: is the Python release past end of life? Django/Flask/FastAPI major versions out of security support (Django non-LTS releases expire fast).
**How to check (JS/TS):** `.nvmrc`, `engines.node`, base images: Node odd/EOL majors; React/Next.js/Angular/Vue majors past support; deprecated packages (`request`, `node-sass`, `moment` in new code).
**Evidence to cite:** Version declaration file:line and the published end-of-life date (cite the source); impact if a security fix is needed.
**Scanner leads:** none — manual (OSV leads on old frameworks are a symptom).
**Common false positives:** Vendor-supported LTS distributions; an upgrade already in progress on a branch (ask the user).

### DEP-04
**How to check (Python):** Version specifiers (`>=`, `*`, no pin) in deployable apps; `pip install` without `-r` lock in Dockerfiles; lock hashes (`pip install --require-hashes -r requirements.txt`); `uv sync --frozen`/`uv sync --locked`; Poetry with a committed `poetry.lock` checked by `poetry check --lock` and installed by `poetry sync` (Poetry 2) or `poetry install --sync` (Poetry 1.x) in CI and images. `poetry install --no-root` only skips the root package; it is not what makes the install locked.
**How to check (JS/TS):** `npm install` vs `npm ci` in CI/Dockerfiles; `pnpm install --frozen-lockfile`; `^`/`~` ranges are fine with a lock; `latest`/`*` versions; lockfile drift (package.json changed without lock).
**Evidence to cite:** Install command file:line and the manifest ranges.
**Scanner leads:** Hadolint DL3013 (pip without pin), DL3016 (npm without pin), DL3008 (apt without pin); Checkov and Trivy (`DS-*`) Dockerfile checks.
**Common false positives:** Ranges in libraries; apt packages unpinned in a pinned-digest base where reproducibility is not a requirement.

### DEP-05
**How to check (Python):** Committed binaries/wheels/`.so`; `setup.py` executing network code; Dockerfile `curl | sh`; base images by tag not digest; `pip install git+https://...`.
**How to check (JS/TS):** `postinstall`/`preinstall` scripts in the root and in dependencies (look in the lockfile for `hasInstallScript`), committed `vendor/*.min.js`, CDN scripts without `integrity=`; GitHub Actions `uses:` by tag or branch.
**Evidence to cite:** File:line of each uncontrolled input (script, binary, action ref, base tag).
**Scanner leads:** zizmor (`unpinned-uses`), actionlint; Hadolint DL3006/DL3007 (untagged/`latest` bases), DL4006; Checkov `CKV_DOCKER_*`, `CKV_GHA_*`.
**Common false positives:** First-party actions (`actions/checkout`) by major tag are a common accepted practice; still report under CICD-09 policy if the threat model requires SHA pinning.

### DEP-06
**How to check (Python):** Read `License` classifiers of direct dependencies only if the engagement asks for license review (context.json goal); look for AGPL/GPL packages in proprietary distributed software.
**How to check (JS/TS):** `license` fields in the lockfile metadata for direct dependencies; copyleft in frontend bundles that are distributed.
**Evidence to cite:** Package, version and license, and the distribution model.
**Scanner leads:** Trivy license leads (`license:<name>`; `extra.category` is Trivy's classification: forbidden, restricted, reciprocal, notice, permissive, unencumbered, unknown). Trivy sees a license only where a lockfile or package metadata records one (npm lockfiles do, `requirements.txt` does not), so missing license leads are not evidence of no obligations.
**Common false positives:** GPL tooling used only at build time; SaaS without distribution. Mark `not_applicable` with reason when licensing is out of the engagement's scope.

### DEP-07
**How to check (Python):** Read the OSV-Scanner and Trivy run records in `run-ledger.json` (status, version, timestamp) and its raw output for unparsed manifests or packages without versions (unpinned requirements, git deps).
**How to check (JS/TS):** Same; note lockfile versions OSV-Scanner or Trivy could not parse and workspaces it skipped.
**Evidence to cite:** Ledger entry (tool, version, status, started_at) and the unresolved items.
**Scanner leads:** OSV-Scanner and Trivy ledger records.
**Common false positives:** none — this check documents limits; it should almost never be `not_reviewed`.

### DEP-08
**How to check (Python):** Compare declared dependencies with imports (`grep -rn "^import \|^from "`); find overlaps (`requests` + `httpx` + `aiohttp`; two date libraries); check critical packages for last release date and maintainer count.
**How to check (JS/TS):** Declared vs imported packages; overlaps (`axios` + `got` + `node-fetch`, `moment` + `dayjs` + `date-fns`, two state libraries); `@types/*` in dependencies; tiny single-maintainer packages in auth or crypto paths.
**Evidence to cite:** Package names with manifest file:line and the import evidence (or none).
**Scanner leads:** none — manual.
**Common false positives:** Packages used via plugins/config strings (pytest plugins, Babel presets, ESLint configs, Django `INSTALLED_APPS`) look unused by import search.

### DEP-09
**How to check (Python):** `.github/dependabot.yml` or `renovate.json` covering `pip`/`uv`/`poetry` ecosystems and Docker; `git log -1 --format=%cs -- uv.lock` for lockfile age; major-version lag of Django/FastAPI/SQLAlchemy.
**How to check (JS/TS):** Same for `npm` ecosystem; open update PR policy; Next.js/React/TypeScript major lag.
**Evidence to cite:** Config file:line, lockfile last-change date, and the lagging majors.
**Scanner leads:** none — manual.
**Common false positives:** Repos where updates are batched deliberately on a documented cadence.

### DEP-10
**How to check (Python):** `--extra-index-url` (dependency-confusion classic) in requirements, Dockerfiles, `pip.conf`, `uv` `[[tool.uv.index]]`, Poetry sources; internal package names that also exist on PyPI; `git+` / URL dependencies.
**How to check (JS/TS):** `.npmrc` registry and scope mapping (`@company:registry=`), unscoped internal names, `github:`/tarball/`file:` deps in `package.json`; lookalike names (typosquats) of popular packages.
**Evidence to cite:** Config file:line and the package names at risk.
**Scanner leads:** none — manual (OSV-Scanner reports known-malicious packages only if an advisory exists).
**Common false positives:** `--index-url` replacing PyPI entirely with a proxy that mirrors it is the safe pattern.

### DEP-11
**How to check (Python):** Compare `.python-version`, `requires-python`, Dockerfile `FROM python:X`, CI `setup-python` `python-version`, `runtime.txt`, serverless runtime settings.
**How to check (JS/TS):** Compare `.nvmrc`, `engines.node`, `packageManager`, CI `setup-node` `node-version`, Dockerfile `FROM node:X`, Vercel/Netlify settings.
**Evidence to cite:** Each declaration file:line with its value; the mismatch.
**Scanner leads:** none — manual.
**Common false positives:** CI matrices that intentionally test several versions including the deployed one.

### DEP-12
**How to check (Python):** `pytest`, `black`, `mypy` in main dependencies instead of a dev group/extra; Dockerfile installing dev groups (`uv sync` without `--no-dev`, `poetry install` without `--only main`).
**How to check (JS/TS):** Test/build tooling in `dependencies`; Docker images running `npm ci` without `--omit=dev` in the final stage; client bundles importing server-only or dev packages.
**Evidence to cite:** Manifest file:line and the image or bundle that includes them.
**Scanner leads:** Hadolint and Checkov Dockerfile rules (indirect); mostly manual.
**Common false positives:** Next.js/Vite apps where build tooling must be present at build stage only; multi-stage images that copy only build output.
