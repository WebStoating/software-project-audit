# Pinned scanner image for software-project-audit. Every value is supplied by
# `--build-arg` from assets/tool-versions.json (see auditlib/dockerutil.py); nothing has a default.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG TARGETARCH

ARG NODE_VERSION
ARG NODE_SHA256_AMD64
ARG NODE_SHA256_ARM64
ARG NODE_URL_AMD64
ARG NODE_URL_ARM64

ARG OSV_SCANNER_VERSION
ARG OSV_SCANNER_URL_AMD64
ARG OSV_SCANNER_URL_ARM64
ARG OSV_SCANNER_SHA256_AMD64
ARG OSV_SCANNER_SHA256_ARM64

ARG GITLEAKS_VERSION
ARG GITLEAKS_URL_AMD64
ARG GITLEAKS_URL_ARM64
ARG GITLEAKS_SHA256_AMD64
ARG GITLEAKS_SHA256_ARM64

ARG HADOLINT_VERSION
ARG HADOLINT_URL_AMD64
ARG HADOLINT_URL_ARM64
ARG HADOLINT_SHA256_AMD64
ARG HADOLINT_SHA256_ARM64

ARG ACTIONLINT_VERSION
ARG ACTIONLINT_URL_AMD64
ARG ACTIONLINT_URL_ARM64
ARG ACTIONLINT_SHA256_AMD64
ARG ACTIONLINT_SHA256_ARM64

ARG TRIVY_VERSION
ARG TRIVY_URL_AMD64
ARG TRIVY_URL_ARM64
ARG TRIVY_SHA256_AMD64
ARG TRIVY_SHA256_ARM64

ARG PY_SEMGREP_VERSION
ARG PY_BANDIT_VERSION
ARG PY_CHECKOV_VERSION
ARG PY_RUFF_VERSION
ARG PY_LIZARD_VERSION
ARG PY_ZIZMOR_VERSION

ARG NPM_JSCPD_VERSION

ARG SEMGREP_PACKS

LABEL org.opencontainers.image.title="software-project-audit-scanners" \
      audit.node="${NODE_VERSION}" \
      audit.osv-scanner="${OSV_SCANNER_VERSION}" \
      audit.gitleaks="${GITLEAKS_VERSION}" \
      audit.hadolint="${HADOLINT_VERSION}" \
      audit.actionlint="${ACTIONLINT_VERSION}" \
      audit.trivy="${TRIVY_VERSION}" \
      audit.semgrep="${PY_SEMGREP_VERSION}" \
      audit.bandit="${PY_BANDIT_VERSION}" \
      audit.checkov="${PY_CHECKOV_VERSION}" \
      audit.ruff="${PY_RUFF_VERSION}" \
      audit.lizard="${PY_LIZARD_VERSION}" \
      audit.zizmor="${PY_ZIZMOR_VERSION}" \
      audit.jscpd="${NPM_JSCPD_VERSION}"

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    HOME=/tmp

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Node (for jscpd), from the pinned tarball, verified with SHA-256.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) url="$NODE_URL_AMD64"; sha="$NODE_SHA256_AMD64" ;; \
      arm64) url="$NODE_URL_ARM64"; sha="$NODE_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/node.tar.xz "$url"; \
    echo "$sha  /tmp/node.tar.xz" | sha256sum -c -; \
    mkdir -p /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1; \
    rm /tmp/node.tar.xz; \
    ln -s /opt/node/bin/node /usr/local/bin/node

RUN /opt/node/bin/npm install -g --prefix /opt/jscpd "jscpd@${NPM_JSCPD_VERSION}" \
 && ln -s /opt/jscpd/bin/jscpd /usr/local/bin/jscpd \
 && /opt/node/bin/npm cache clean --force

# Standalone binaries: each download is verified with sha256sum -c before it is installed.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) url="$OSV_SCANNER_URL_AMD64"; sha="$OSV_SCANNER_SHA256_AMD64" ;; \
      arm64) url="$OSV_SCANNER_URL_ARM64"; sha="$OSV_SCANNER_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/dl "$url"; \
    echo "$sha  /tmp/dl" | sha256sum -c -; \
    install -m 0755 /tmp/dl /usr/local/bin/osv-scanner; \
    rm /tmp/dl

RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) url="$HADOLINT_URL_AMD64"; sha="$HADOLINT_SHA256_AMD64" ;; \
      arm64) url="$HADOLINT_URL_ARM64"; sha="$HADOLINT_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/dl "$url"; \
    echo "$sha  /tmp/dl" | sha256sum -c -; \
    install -m 0755 /tmp/dl /usr/local/bin/hadolint; \
    rm /tmp/dl

RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) url="$GITLEAKS_URL_AMD64"; sha="$GITLEAKS_SHA256_AMD64" ;; \
      arm64) url="$GITLEAKS_URL_ARM64"; sha="$GITLEAKS_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/dl.tgz "$url"; \
    echo "$sha  /tmp/dl.tgz" | sha256sum -c -; \
    mkdir /tmp/x; tar -xzf /tmp/dl.tgz -C /tmp/x gitleaks; \
    install -m 0755 /tmp/x/gitleaks /usr/local/bin/gitleaks; \
    rm -rf /tmp/dl.tgz /tmp/x

RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) url="$ACTIONLINT_URL_AMD64"; sha="$ACTIONLINT_SHA256_AMD64" ;; \
      arm64) url="$ACTIONLINT_URL_ARM64"; sha="$ACTIONLINT_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/dl.tgz "$url"; \
    echo "$sha  /tmp/dl.tgz" | sha256sum -c -; \
    mkdir /tmp/x; tar -xzf /tmp/dl.tgz -C /tmp/x actionlint; \
    install -m 0755 /tmp/x/actionlint /usr/local/bin/actionlint; \
    rm -rf /tmp/dl.tgz /tmp/x

# Trivy: v0.69.4 binaries were malicious (GHSA-69fq-xp46-6x23). The pinned post-incident release's
# SHA-256 values come from its sigstore-verified trivy_<ver>_checksums.txt (see tool-versions.json).
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) url="$TRIVY_URL_AMD64"; sha="$TRIVY_SHA256_AMD64" ;; \
      arm64) url="$TRIVY_URL_ARM64"; sha="$TRIVY_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/dl.tgz "$url"; \
    echo "$sha  /tmp/dl.tgz" | sha256sum -c -; \
    mkdir /tmp/x; tar -xzf /tmp/dl.tgz -C /tmp/x trivy; \
    install -m 0755 /tmp/x/trivy /usr/local/bin/trivy; \
    rm -rf /tmp/dl.tgz /tmp/x

# Python tools, each in its own venv so their dependency trees cannot conflict.
RUN set -eu; \
    for spec in "semgrep==${PY_SEMGREP_VERSION}" "bandit==${PY_BANDIT_VERSION}" \
                "checkov==${PY_CHECKOV_VERSION}" "ruff==${PY_RUFF_VERSION}" \
                "lizard==${PY_LIZARD_VERSION}" "zizmor==${PY_ZIZMOR_VERSION}"; do \
      name="${spec%%==*}"; \
      python -m venv "/opt/venvs/$name"; \
      "/opt/venvs/$name/bin/pip" install "$spec"; \
      ln -s "/opt/venvs/$name/bin/$name" "/usr/local/bin/$name"; \
    done

# Semgrep rule snapshot: the scanner runs offline against these files with --metrics=off.
RUN set -eu; \
    mkdir -p /rules; \
    for pack in ${SEMGREP_PACKS}; do \
      slug="$(echo "$pack" | tr '/' '-')"; \
      curl -fsSL "https://semgrep.dev/c/${pack}" -o "/rules/${slug}.yml"; \
    done; \
    date -u +%Y-%m-%d > /rules/SNAPSHOT; \
    chmod -R a+rX /rules

RUN git config --system safe.directory '*' \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin scanner \
 && mkdir -p /src /out \
 && chown scanner /src /out

WORKDIR /src
USER 10001
