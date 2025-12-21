#!/usr/bin/env bash
set -euo pipefail

# Repo Dump script: creates ONE ZIP for THIS repo only.
# Output directory (fixed): ~/Documents/Backups/Dumps/
# ZIP name format: <repoFolderName>__YYYY-MM-DD__HHMMSS.zip
#
# Usage:
#   bash tools/dump_repo_zip.sh

OUT_DIR="${HOME}/Documents/Backups/Dumps"
TS="$(date '+%Y-%m-%d__%H%M%S')"

# Repo root = parent of this script's directory (tools/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_NAME="$(basename "${ROOT_DIR}")"

# "Code-relevante" Includes (zip patterns)
INCLUDE_PATTERNS=(
  "*.ts" "*.tsx" "*.js" "*.jsx"
  "*.py"
  "*.md"
  "*.json"
  "*.yml" "*.yaml"
  "*.toml"
  ".env.example"
  "*.sql"
  "*.prisma"
  "*.graphql"
  "*.sh"
  "*.css" "*.scss"
  "*.html"
  "*.txt"
  "*.lock"
)

# Typical noise excludes (zip patterns)
EXCLUDE_PATTERNS=(
  ".git/*" "*/.git/*"
  "node_modules/*" "*/node_modules/*"
  ".next/*" "*/.next/*"
  "dist/*" "*/dist/*"
  "build/*" "*/build/*"
  ".venv/*" "*/.venv/*"
  "venv/*" "*/venv/*"
  "__pycache__/*" "*/__pycache__/*"
  ".pytest_cache/*" "*/.pytest_cache/*"
  ".DS_Store" "*/.DS_Store"
  "coverage/*" "*/coverage/*"
  ".turbo/*" "*/.turbo/*"
  ".cache/*" "*/.cache/*"
  "tmp/*" "*/tmp/*"
  "logs/*" "*/logs/*"
)

mkdir -p "${OUT_DIR}"

has_relevant_files() {
  local dir="$1"
  local -a find_args=()
  find_args+=( "${dir}" )

  # Prune noise directories
  find_args+=( \( )
  find_args+=( -name ".git" -o -name "node_modules" -o -name ".next" -o -name "dist" -o -name "build" )
  find_args+=( -o -name ".venv" -o -name "venv" -o -name "__pycache__" -o -name ".pytest_cache" )
  find_args+=( -o -name "coverage" -o -name ".turbo" -o -name ".cache" -o -name "tmp" -o -name "logs" )
  find_args+=( \) -prune -o )

  # Match relevant files
  find_args+=( -type f \( )
  find_args+=( -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" )
  find_args+=( -o -name "*.py" )
  find_args+=( -o -name "*.md" )
  find_args+=( -o -name "*.json" )
  find_args+=( -o -name "*.yml" -o -name "*.yaml" )
  find_args+=( -o -name "*.toml" )
  find_args+=( -o -name ".env.example" )
  find_args+=( -o -name "*.sql" )
  find_args+=( -o -name "*.prisma" )
  find_args+=( -o -name "*.graphql" )
  find_args+=( -o -name "*.sh" )
  find_args+=( -o -name "*.css" -o -name "*.scss" )
  find_args+=( -o -name "*.html" )
  find_args+=( -o -name "*.txt" )
  find_args+=( -o -name "*.lock" )
  find_args+=( \) -print -quit )

  find "${find_args[@]}" >/dev/null 2>&1
}

echo ""
echo "=== Repo Dump: ${REPO_NAME} ==="

if ! has_relevant_files "${ROOT_DIR}"; then
  echo "Skipped: no relevant code files found."
  exit 0
fi

ZIP_PATH="${OUT_DIR}/${REPO_NAME}__${TS}.zip"

(
  cd "${ROOT_DIR}"
  zip -qry "${ZIP_PATH}" . \
    -i "${INCLUDE_PATTERNS[@]}" \
    -x "${EXCLUDE_PATTERNS[@]}"
)

echo "Created:"
echo "  - $(du -h "${ZIP_PATH}" | awk '{print $1}')  ${ZIP_PATH}"


