#!/usr/bin/env bash
# Symlink the software-project-audit skill into the Claude Code and Codex user skill directories.
#
# Usage: ./install.sh [--claude-dir DIR] [--codex-dir DIR] [--no-claude] [--no-codex] [--uninstall]
#
#   --claude-dir DIR  Claude Code skills directory
#                     (default: ${CLAUDE_CONFIG_DIR:-$HOME/.claude}/skills)
#   --codex-dir DIR   Codex skills directory (default: $HOME/.agents/skills, the user-level
#                     location in the OpenAI Codex docs: https://developers.openai.com/codex/skills)
#   --no-claude       Skip Claude Code (install or uninstall for Codex only)
#   --no-codex        Skip Codex (install or uninstall for Claude Code only)
#   --uninstall       Remove the links, but only links that point at this repository's skill folder
#
# The link is DIR/software-project-audit. An existing link to this skill is left as is, so
# re-running is safe. Anything else at that path (a real directory or file, or a link to
# another folder) is never touched: the script reports it and exits 1 without installing anything.
set -euo pipefail

NAME="software-project-audit"
REPO_DIR="$(cd "$(dirname "$0")" && pwd -P)"
SKILL_DIR="$REPO_DIR/$NAME/skills/audit"

usage() {
    sed -n '4,12p' "$0" | sed 's/^# \{0,1\}//'
}

claude_dir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/skills"
codex_dir="$HOME/.agents/skills"
uninstall=0
want_claude=1
want_codex=1

while [ $# -gt 0 ]; do
    case "$1" in
        --claude-dir)
            [ $# -ge 2 ] || { echo "install.sh: --claude-dir needs a directory" >&2; exit 2; }
            claude_dir="$2"; shift 2 ;;
        --codex-dir)
            [ $# -ge 2 ] || { echo "install.sh: --codex-dir needs a directory" >&2; exit 2; }
            codex_dir="$2"; shift 2 ;;
        --no-claude) want_claude=0; shift ;;
        --no-codex) want_codex=0; shift ;;
        --uninstall) uninstall=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "install.sh: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ ! -f "$SKILL_DIR/SKILL.md" ]; then
    echo "install.sh: skill folder not found at $SKILL_DIR" >&2
    exit 1
fi

# True when $1 is a symlink whose target is this repository's skill folder.
points_at_skill() {
    local link="$1" target resolved
    [ -L "$link" ] || return 1
    target="$(readlink "$link")"
    [ "$target" = "$SKILL_DIR" ] && return 0
    resolved="$(cd "$link" 2>/dev/null && pwd -P)" || return 1
    [ "$resolved" = "$SKILL_DIR" ]
}

if [ "$want_claude" -eq 0 ] && [ "$want_codex" -eq 0 ]; then
    echo "install.sh: --no-claude and --no-codex together leave nothing to do" >&2
    exit 2
fi
targets=""
[ "$want_claude" -eq 1 ] && targets="$claude_dir/$NAME"
if [ "$want_codex" -eq 1 ]; then
    targets="${targets:+$targets
}$codex_dir/$NAME"
fi

if [ "$uninstall" -eq 1 ]; then
    while IFS= read -r link; do
        if points_at_skill "$link"; then
            rm -- "$link"
            echo "removed $link"
        elif [ -e "$link" ] || [ -L "$link" ]; then
            echo "left $link in place: it is not a link to $SKILL_DIR"
        else
            echo "nothing to remove at $link"
        fi
    done <<EOF
$targets
EOF
    exit 0
fi

# Check every target before changing anything.
conflict=0
while IFS= read -r link; do
    if [ -L "$link" ] && ! points_at_skill "$link"; then
        echo "install.sh: $link is a symlink to $(readlink "$link"), not to $SKILL_DIR; refusing to replace it" >&2
        conflict=1
    elif [ -e "$link" ] && [ ! -L "$link" ]; then
        echo "install.sh: $link exists and is not a symlink; refusing to overwrite it (move it away and rerun)" >&2
        conflict=1
    fi
done <<EOF
$targets
EOF
[ "$conflict" -eq 0 ] || exit 1

while IFS= read -r link; do
    if points_at_skill "$link"; then
        echo "already installed: $link -> $SKILL_DIR"
    else
        mkdir -p -- "$(dirname "$link")"
        ln -s -- "$SKILL_DIR" "$link"
        echo "installed: $link -> $SKILL_DIR"
    fi
done <<EOF
$targets
EOF
