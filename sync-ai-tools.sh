#!/usr/bin/env bash
set -euo pipefail

REMOTE_NAME="ai-tools"
REMOTE_BRANCH="master"
REMOTE_SUBDIR="vyper-sit-toolkit"
REPO_ROOT="$(git rev-parse --show-toplevel)"

require_clean_worktree() {
    if [[ -n "$(git status --porcelain)" ]]; then
        echo "Working tree is not clean. Commit or stash changes before syncing."
        exit 1
    fi
}

require_no_tracked_changes() {
    if git status --porcelain | grep -qv '^?? '; then
        echo "Tracked files have uncommitted changes. Commit or stash them before pushing."
        exit 1
    fi
}

require_remote() {
    if ! git remote get-url "$REMOTE_NAME" >/dev/null 2>&1; then
        echo "Remote '$REMOTE_NAME' is not configured."
        exit 1
    fi
}

make_checkout() {
    CHECKOUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ai-tools-sync.XXXXXX")"
    IGNORED_PATHS_FILE="$(mktemp "${TMPDIR:-/tmp}/ai-tools-ignored.XXXXXX")"
    trap 'rm -rf "$CHECKOUT_DIR"; rm -f "$IGNORED_PATHS_FILE"' EXIT
    git -C "$REPO_ROOT" ls-files --others --ignored --exclude-standard --directory > "$IGNORED_PATHS_FILE"
    git clone --branch "$REMOTE_BRANCH" --single-branch "$(git remote get-url "$REMOTE_NAME")" "$CHECKOUT_DIR"
    if [[ ! -d "$CHECKOUT_DIR/$REMOTE_SUBDIR" ]]; then
        echo "Remote directory '$REMOTE_SUBDIR' does not exist on $REMOTE_NAME/$REMOTE_BRANCH."
        exit 1
    fi
}

sync_from_remote() {
    require_clean_worktree
    make_checkout
    rsync -ani --delete \
        --exclude='.git/' \
        --exclude-from="$IGNORED_PATHS_FILE" \
        --exclude='.gitignore' \
        --exclude='sync-ai-tools.sh' \
        --exclude='.ai-tools-sync' \
        --exclude='.DS_Store' \
        "$CHECKOUT_DIR/$REMOTE_SUBDIR/" "$REPO_ROOT/"
    read -r -p "Apply this pull preview to the local SIT repository? [y/N] " reply
    if [[ "$reply" =~ ^[Yy]$ ]]; then
        rsync -ai --delete \
            --exclude='.git/' \
            --exclude-from="$IGNORED_PATHS_FILE" \
            --exclude='.gitignore' \
            --exclude='sync-ai-tools.sh' \
            --exclude='.ai-tools-sync' \
            --exclude='.DS_Store' \
            "$CHECKOUT_DIR/$REMOTE_SUBDIR/" "$REPO_ROOT/"
        echo "Pull complete. Review the result with git status."
    else
        echo "Pull cancelled."
    fi
}

sync_to_remote() {
    require_no_tracked_changes
    make_checkout
    rsync -ani --delete \
        --exclude='.git/' \
        --exclude-from="$IGNORED_PATHS_FILE" \
        --exclude='.gitignore' \
        --exclude='sync-ai-tools.sh' \
        --exclude='.ai-tools-sync' \
        --exclude='.DS_Store' \
        "$REPO_ROOT/" "$CHECKOUT_DIR/$REMOTE_SUBDIR/"
    read -r -p "Apply this push preview to $REMOTE_NAME/$REMOTE_BRANCH/$REMOTE_SUBDIR? [y/N] " reply
    if [[ ! "$reply" =~ ^[Yy]$ ]]; then
        echo "Push cancelled."
        return
    fi
    rsync -ai --delete \
        --exclude='.git/' \
        --exclude-from="$IGNORED_PATHS_FILE" \
        --exclude='.gitignore' \
        --exclude='sync-ai-tools.sh' \
        --exclude='.ai-tools-sync' \
        --exclude='.DS_Store' \
        "$REPO_ROOT/" "$CHECKOUT_DIR/$REMOTE_SUBDIR/"
    git -C "$CHECKOUT_DIR" add --all "$REMOTE_SUBDIR"
    if git -C "$CHECKOUT_DIR" diff --cached --quiet; then
        echo "No changes to push."
        return
    fi
    git -C "$CHECKOUT_DIR" diff --cached --stat
    read -r -p "Commit and push only these $REMOTE_SUBDIR changes? [y/N] " reply
    if [[ "$reply" =~ ^[Yy]$ ]]; then
        git -C "$CHECKOUT_DIR" commit -m "Sync vyper-sit-toolkit from SIT"
        git -C "$CHECKOUT_DIR" push origin "$REMOTE_BRANCH"
        echo "Push complete. Other ai-tools directories were preserved."
    else
        echo "Push cancelled."
    fi
}

show_status() {
    require_remote
    git fetch "$REMOTE_NAME" "$REMOTE_BRANCH"
    echo "Remote: $(git remote get-url "$REMOTE_NAME")"
    echo "Mapping: $REPO_ROOT -> $REMOTE_NAME/$REMOTE_BRANCH/$REMOTE_SUBDIR"
    git log -1 --format='Remote HEAD: %h %s' "$REMOTE_NAME/$REMOTE_BRANCH"
    git status --short --branch
}

case "${1:-status}" in
    pull) sync_from_remote ;;
    push) sync_to_remote ;;
    status) show_status ;;
    *) echo "Usage: $0 {pull|push|status}"; exit 1 ;;
esac
