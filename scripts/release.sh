#!/usr/bin/env bash
set -euo pipefail

VERSION="dev"
OUT_DIR="dist"
CLEAN=0
SKIP_TESTS=0
NO_COLOR_FLAG=0
NO_ARCHIVES=0
TARGETS=(
  "windows/386"
  "windows/amd64"
  "windows/arm64"
  "linux/386"
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
)

usage() {
  cat <<'EOF'
Usage: scripts/release.sh [options]

Options:
  --version VALUE      Version label used in output names. Default: dev
  --out-dir PATH       Directory for release artifacts. Default: dist
  --clean              Remove the output directory before building
  --skip-tests         Skip go test ./...
  --targets LIST       Comma-separated GOOS/GOARCH targets
  --no-archives        Build binaries without zip/tar.gz release bundles
  --no-color           Disable colored status output
  --help               Show this help

Default targets:
  windows/386, windows/amd64, windows/arm64,
  linux/386, linux/amd64, linux/arm64,
  darwin/amd64, darwin/arm64
EOF
}

arch_label() {
  case "$1" in
    386) echo "x86" ;;
    amd64) echo "x64" ;;
    *) echo "$1" ;;
  esac
}

color_code() {
  case "$1" in
    cyan) echo "36" ;;
    green) echo "32" ;;
    magenta) echo "35" ;;
    yellow) echo "33" ;;
    red) echo "31" ;;
    *) echo "0" ;;
  esac
}

release_status() {
  local kind="$1"
  local message="$2"
  local color="${3:-}"

  if [[ "${COLOR_OUTPUT:-0}" -eq 1 && -n "$color" ]]; then
    printf '\033[%sm[%s]\033[0m %s\n' "$(color_code "$color")" "$kind" "$message"
  else
    printf '[%s] %s\n' "$kind" "$message"
  fi
}

release_warning() {
  local message="$1"

  if [[ "${COLOR_OUTPUT:-0}" -eq 1 ]]; then
    printf '\033[33m[warn]\033[0m %s\n' "$message" >&2
  else
    printf '[warn] %s\n' "$message" >&2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION="${2:?--version requires a value}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:?--out-dir requires a value}"
      shift 2
      ;;
    --clean)
      CLEAN=1
      shift
      ;;
    --skip-tests)
      SKIP_TESTS=1
      shift
      ;;
    --no-color)
      NO_COLOR_FLAG=1
      shift
      ;;
    --no-archives)
      NO_ARCHIVES=1
      shift
      ;;
    --targets)
      IFS=',' read -r -a TARGETS <<< "${2:?--targets requires a value}"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

COLOR_OUTPUT=0
if [[ "$NO_COLOR_FLAG" -eq 0 && -z "${NO_COLOR:-}" && -t 1 ]]; then
  COLOR_OUTPUT=1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_PARENT="$(dirname "$OUT_DIR")"
DIST_BASE="$(basename "$OUT_DIR")"

mkdir -p "$REPO_ROOT/$DIST_PARENT"
DIST_PARENT_ABS="$(cd "$REPO_ROOT/$DIST_PARENT" && pwd)"
DIST_ROOT="$DIST_PARENT_ABS/$DIST_BASE"

case "$DIST_ROOT" in
  "$REPO_ROOT"/*) ;;
  *)
    echo "Refusing to operate outside repo root: $DIST_ROOT" >&2
    exit 1
    ;;
esac

cd "$REPO_ROOT"

if ! command -v go >/dev/null 2>&1; then
  echo "go command not found. Install Go or add it to PATH before running the release script." >&2
  exit 1
fi

if [[ "$CLEAN" -eq 1 && -e "$DIST_ROOT" ]]; then
  rm -rf "$DIST_ROOT"
fi

mkdir -p "$DIST_ROOT"

if [[ "$SKIP_TESTS" -eq 0 ]]; then
  release_status "test" "go test ./..." "cyan"
  go test ./...
fi

SUPPORTED_TARGETS="$(go tool dist list)"
SAFE_VERSION="$(printf '%s' "$VERSION" | sed 's/[^A-Za-z0-9._-]/-/g')"
BUILD_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || true)"
if [[ -z "$BUILD_COMMIT" ]]; then
  BUILD_COMMIT="unknown"
fi
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUILT=()
CHECKSUMS_FILE="$DIST_ROOT/SHA256SUMS.txt"
: > "$CHECKSUMS_FILE"

checksum_line() {
  local path="$1"
  local name="$2"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk -v name="$name" '{print $1 "  " name}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk -v name="$name" '{print $1 "  " name}'
    return
  fi
  release_warning "No SHA-256 tool found; checksum skipped for $name"
}

copy_package_item() {
  local package_root="$1"
  local relative_path="$2"

  if [[ -e "$REPO_ROOT/$relative_path" ]]; then
    cp -R "$REPO_ROOT/$relative_path" "$package_root/"
  fi
}

create_archive() {
  local goos="$1"
  local package_name="$2"
  local archive_name=""

  if [[ "$goos" == "windows" ]]; then
    archive_name="$package_name.zip"
    if ! command -v zip >/dev/null 2>&1; then
      release_warning "Skipping archive for $package_name because zip was not found"
      return
    fi
    (cd "$DIST_ROOT" && zip -qr "$archive_name" "$package_name")
  else
    archive_name="$package_name.tar.gz"
    if ! command -v tar >/dev/null 2>&1; then
      release_warning "Skipping archive for $package_name because tar was not found"
      return
    fi
    tar -czf "$DIST_ROOT/$archive_name" -C "$DIST_ROOT" "$package_name"
  fi

  printf '%s\n' "$archive_name"
}

for target in "${TARGETS[@]}"; do
  target="${target//[[:space:]]/}"
  if [[ "$target" != */* ]]; then
    release_warning "Skipping invalid target '$target'; expected GOOS/GOARCH"
    continue
  fi

  goos="${target%%/*}"
  goarch="${target##*/}"
  target_name="$goos/$goarch"

  if ! printf '%s\n' "$SUPPORTED_TARGETS" | grep -qx "$target_name"; then
    release_warning "Skipping unsupported Go target: $target_name"
    continue
  fi

  label="$(arch_label "$goarch")"
  extension=""
  if [[ "$goos" == "windows" ]]; then
    extension=".exe"
  fi

  output_name="catsonbroadway-$SAFE_VERSION-$goos-$label$extension"
  output_path="$DIST_ROOT/$output_name"
  package_name="catsonbroadway-$SAFE_VERSION-$goos-$label"
  package_root="$DIST_ROOT/$package_name"

  release_status "build" "$target_name -> $output_name" "green"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags="-s -w -X main.buildVersion=$SAFE_VERSION -X main.buildCommit=$BUILD_COMMIT -X main.buildDate=$BUILD_DATE -X main.buildTarget=$target_name" -o "$output_path" .

  checksum_line "$output_path" "$output_name" >> "$CHECKSUMS_FILE"

  archive_name=""
  if [[ "$NO_ARCHIVES" -eq 0 ]]; then
    release_status "archive" "$target_name -> $package_name" "cyan"
    rm -rf "$package_root"
    mkdir -p "$package_root"
    cp "$output_path" "$package_root/"
    copy_package_item "$package_root" "README.md"
    copy_package_item "$package_root" "cert_config.json"
    copy_package_item "$package_root" "headers.json"
    copy_package_item "$package_root" "stage_options"
    copy_package_item "$package_root" "payload_options"
    archive_name="$(create_archive "$goos" "$package_name")"
    if [[ -n "$archive_name" ]]; then
      checksum_line "$DIST_ROOT/$archive_name" "$archive_name" >> "$CHECKSUMS_FILE"
    fi
    rm -rf "$package_root"
  fi

  BUILT+=("$target_name $output_name $archive_name")
done

echo
release_status "done" "Release artifacts written to $DIST_ROOT" "magenta"
printf '%s\n' "${BUILT[@]}"
