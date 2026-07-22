#!/bin/bash

# Sync script for vyper-sit-toolkit folder from ai-tools repository
# Usage: ./sync-ai-tools.sh [pull|push|status|help]

set -e

REMOTE_NAME="ai-tools"
REMOTE_BRANCH="master"
REMOTE_SUBFOLDER="vyper-sit-toolkit"
TEMP_DIR="temp-ai-tools-sync"

function show_usage() {
    echo "Usage: $0 [pull|push|status|help]"
    echo ""
    echo "Commands:"
    echo "  pull    - Pull changes from ai-tools/vyper-sit-toolkit to local SIT"
    echo "  push    - Push local SIT changes to ai-tools/vyper-sit-toolkit"
    echo "  status  - Show sync status and differences"
    echo "  help    - Show this help message"
}

function pull_changes() {
    echo "🔄 Pulling changes from $REMOTE_NAME/$REMOTE_SUBFOLDER..."
    
    # Fetch latest changes
    git fetch $REMOTE_NAME $REMOTE_BRANCH
    
    # Create temporary directory
    rm -rf $TEMP_DIR
    mkdir -p $TEMP_DIR
    
    # Clone the remote repository to temp directory
    git clone --depth 1 --branch $REMOTE_BRANCH $(git remote get-url $REMOTE_NAME) $TEMP_DIR
    
    # Check if the subfolder exists
    if [ ! -d "$TEMP_DIR/$REMOTE_SUBFOLDER" ]; then
        echo "❌ Subfolder $REMOTE_SUBFOLDER not found in remote repository"
        rm -rf $TEMP_DIR
        exit 1
    fi
    
    # Show what will be copied (dry run first)
    echo "📋 Files that will be synced:"
    rsync -av --dry-run --exclude='.git*' --exclude='*.pyc' --exclude='__pycache__' \
          --exclude='node_modules' --exclude='.DS_Store' --exclude='sync-ai-tools.sh' \
          --exclude='SYNC_README.md' \
          $TEMP_DIR/$REMOTE_SUBFOLDER/ ./
    
    echo ""
    read -p "Continue with sync? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Sync cancelled"
        rm -rf $TEMP_DIR
        exit 0
    fi
    
    # Copy files (excluding .git and other metadata)
    rsync -av --exclude='.git*' --exclude='*.pyc' --exclude='__pycache__' \
          --exclude='node_modules' --exclude='.DS_Store' --exclude='sync-ai-tools.sh' \
          --exclude='SYNC_README.md' \
          $TEMP_DIR/$REMOTE_SUBFOLDER/ ./
    
    # Clean up
    rm -rf $TEMP_DIR
    
    echo "✅ Pull completed. Review changes with 'git status' and commit if needed."
}

function push_changes() {
    echo "🚀 Pushing local changes to $REMOTE_NAME/$REMOTE_SUBFOLDER..."
    
    # Check if there are uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        echo "⚠️  You have uncommitted changes. Please commit them first or stash them."
        echo "Current status:"
        git status --porcelain
        exit 1
    fi
    
    # Create temporary directory for ai-tools checkout (avoids massive files in workspace)
    TEMP_WORKTREE_DIR="../temp-ai-tools-worktree-$(date +%s)"
    TEMP_BRANCH="temp-sync-$(date +%s)"
    
    # Fetch the latest remote state
    git fetch $REMOTE_NAME $REMOTE_BRANCH
    
    echo "📁 Creating temporary worktree (avoids downloading massive files to current workspace)..."
    
    # Create a git worktree in a separate directory
    git worktree add $TEMP_WORKTREE_DIR $REMOTE_NAME/$REMOTE_BRANCH
    
    # Change to the worktree directory
    cd $TEMP_WORKTREE_DIR
    
    # Create an orphan branch (no history) to avoid large files
    echo "🌿 Creating clean orphan branch to avoid large file history..."
    git checkout --orphan $TEMP_BRANCH
    
    # Remove all files except vyper-sit-toolkit to start clean
    find . -maxdepth 1 -not -name '.' -not -name '.git' -not -name "$REMOTE_SUBFOLDER" -exec rm -rf {} + 2>/dev/null || true
    
    # Clear the vyper-sit-toolkit folder and copy our local changes
    echo "🧹 Clearing existing $REMOTE_SUBFOLDER folder..."
    rm -rf ./$REMOTE_SUBFOLDER/*
    
    # Copy our local changes to the subfolder, excluding sync files and large directories
    echo "📋 Copying SIT repository to $REMOTE_SUBFOLDER..."
    rsync -av --exclude='.git*' --exclude='*.pyc' --exclude='__pycache__' \
          --exclude='node_modules' --exclude='.DS_Store' \
          --exclude='sync-ai-tools.sh' --exclude='SYNC_README.md' \
          --exclude='venv/' --exclude='.pytest_cache/' \
          --exclude='netsec-feature_test_lib-aleroyds/' \
          --exclude='temp-ai-tools-*' \
          ../SIT/ ./$REMOTE_SUBFOLDER/
    
    # Add and commit ONLY changes in the vyper-sit-toolkit folder
    echo "📝 Adding only vyper-sit-toolkit changes to git..."
    git add ./$REMOTE_SUBFOLDER/
    if git diff --cached --quiet; then
        echo "ℹ️  No changes to push."
    else
        echo "📝 Changes to be committed:"
        git diff --cached --stat
        echo ""
        read -p "Continue with push? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git commit -m "Sync changes from SIT repo $(date)"
            echo "📤 Force pushing clean branch to $REMOTE_NAME/$REMOTE_BRANCH..."
            git push --force-with-lease origin $TEMP_BRANCH:$REMOTE_BRANCH
            echo "✅ Push completed successfully!"
        else
            echo "❌ Push cancelled"
        fi
    fi
    
    # Return to original directory and cleanup
    cd - > /dev/null
    git worktree remove $TEMP_WORKTREE_DIR
    echo "🧹 Cleaned up temporary worktree"
}

function show_status() {
    echo "📊 Sync Status for $REMOTE_NAME/$REMOTE_SUBFOLDER"
    echo "================================================"
    
    # Fetch latest
    git fetch $REMOTE_NAME $REMOTE_BRANCH
    
    # Show remote info
    echo "Remote: $(git remote get-url $REMOTE_NAME)"
    echo "Branch: $REMOTE_BRANCH"
    echo "Last remote commit: $(git log -1 --format='%cd (%h) %s' $REMOTE_NAME/$REMOTE_BRANCH)"
    echo ""
    
    # Check for local uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        echo "⚠️  You have uncommitted local changes:"
        git status --porcelain | head -10
        local total_changes=$(git status --porcelain | wc -l)
        if [ $total_changes -gt 10 ]; then
            echo "... and $((total_changes - 10)) more files"
        fi
        echo ""
    else
        echo "✅ No uncommitted local changes"
        echo ""
    fi
    
    # Show last local commit
    echo "Last local commit: $(git log -1 --format='%cd (%h) %s')"
    echo ""
    
    echo "💡 Use 'git log --oneline $REMOTE_NAME/$REMOTE_BRANCH' to see remote commits"
    echo "💡 Use './sync-ai-tools.sh pull' to sync from remote"
    echo "💡 Use './sync-ai-tools.sh push' to sync to remote"
}

# Main script logic
case "${1:-help}" in
    pull)
        pull_changes
        ;;
    push)
        push_changes
        ;;
    status)
        show_status
        ;;
    help|*)
        show_usage
        ;;
esac
