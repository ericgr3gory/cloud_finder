#!/usr/bin/env bash
set -euo pipefail

DEST_DIR="${1:-$HOME/dictionaries}"
mkdir -p "$DEST_DIR"

URLS=(
  "https://hashmob.net/api/v2/downloads/research/official/hashmob.net_2026-05-10.medium.found.7z"
  "https://hashmob.net/api/v2/downloads/research/official/hashmob.net_2026-05-10.larger.found.7z"
  "https://hashmob.net/api/v2/downloads/research/official/hashmob.net_2026-05-10.small.found.7z"
  "https://hashmob.net/api/v2/downloads/research/official/hashmob.net_2026-05-10.tiny.found.7z"
  "https://weakpass.com/download/2093/triple-h.txt.7z"
  "https://weakpass.com/download/1256/hk_hlm_founds.txt.gz"
  "https://weakpass.com/download/1938/kaonashi14M.txt.7z"
  "https://weakpass.com/download/2080/hashpwn.txt.7z"
  "https://weakpass.com/download/87/rockyou-65.txt.gz"
  "https://weakpass.com/download/2017/weakpass_4a.latin.txt.7z"
)

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required command: $1"
        exit 1
    }
}

require_cmd curl
require_cmd 7z
require_cmd gunzip

extract_and_cleanup() {
    local file="$1"

    case "$file" in
        *.7z)
            echo "[EXTRACT] $(basename "$file")"
            if 7z x -y -o"$DEST_DIR" "$file"; then
                echo "[DELETE] $(basename "$file")"
                rm -f "$file"
            fi
            ;;
        *.gz)
            local out="${DEST_DIR}/$(basename "${file%.gz}")"
            echo "[EXTRACT] $(basename "$file")"
            if gunzip -c "$file" > "$out"; then
                echo "[DELETE] $(basename "$file")"
                rm -f "$file"
            else
                rm -f "$out"
                exit 1
            fi
            ;;
        *)
            echo "[WARN] Unknown archive format: $file"
            ;;
    esac
}

echo "Destination: $DEST_DIR"
echo

for url in "${URLS[@]}"; do
    file="$DEST_DIR/$(basename "$url")"

    echo "[DOWNLOAD] $url"
    curl -L --fail --retry 3 --retry-delay 5 -o "$file" "$url"

    extract_and_cleanup "$file"
    echo
done

echo "Done."
