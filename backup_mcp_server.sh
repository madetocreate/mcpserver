#!/usr/bin/env zsh
set -e
set +H
unsetopt BANG_HIST

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_NAME="mcp-server"
SRC_DIR="$BASE_DIR"

BACKUP_BASE="$HOME/Documents/uploads/backups"
mkdir -p "$BACKUP_BASE"

TS="$(date +"%Y%m%d-%H%M%S")"
ARCHIVE="$BACKUP_BASE/${PROJECT_NAME}-${TS}.zip"

cd "$SRC_DIR"

zip -r "$ARCHIVE" . \
  -x ".git/*" "*/.git/*" \
     "node_modules/*" "*/node_modules/*" \
     "venv/*" "*/venv/*" \
     "__pycache__/*" "*/__pycache__/*" \
     "*.log" "dist/*" "build/*" "tmp/*" "*.swp"

echo "$ARCHIVE"
