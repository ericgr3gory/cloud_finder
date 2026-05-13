#!/usr/bin/env bash
set -euo pipefail

WORKER_USER="hashcat"
WORKER_HOME="/home/${WORKER_USER}"
DEST_DIR="${WORKER_HOME}/.hashcat/dictionaries"

mkdir -p "$DEST_DIR"
chown -R "${WORKER_USER}:${WORKER_USER}" "${WORKER_HOME}/.hashcat/dictionaries"

URLS=(
  "https://hashmob.net/api/v2/downloads/research/official/hashmob.net_2026-05-10.found.7z"  
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
require_cmd split
require_cmd wc

split_file_four() {
    local file="$1"

    [[ -f "$file" ]] || return 0

    local lines
    lines=$(wc -l < "$file")

    if [[ "$lines" -eq 0 ]]; then
        echo "[SKIP] Empty file: $(basename "$file")"
        return 0
    fi

    local per_chunk=$(( (lines + 3) / 4 ))
    local dir
    dir="$(dirname "$file")"

    local base
    base="$(basename "$file")"

    local stem="${base%.*}"
    local ext=""
    [[ "$base" == *.* ]] && ext=".${base##*.}"

    echo "[SPLIT] $base into 4 parts"

    split -d \
        -l "$per_chunk" \
        --additional-suffix="$ext" \
        "$file" \
        "${dir}/${stem}_"

    local i=0
    for f in "${dir}/${stem}_"*"$ext"; do
        [[ -f "$f" ]] || continue
        mv "$f" "${dir}/${stem}_$((++i))${ext}"
    done
}

extract_and_process() {
    local archive="$1"

    case "$archive" in
        *.7z)
            echo "[EXTRACT] $(basename "$archive")"

            local before
            before=$(mktemp)

            find "$DEST_DIR" -maxdepth 1 -type f > "$before"

            7z x -y -o"$DEST_DIR" "$archive"

            echo "[DELETE] $(basename "$archive")"
            rm -f "$archive"

            while read -r extracted; do
                grep -qxF "$extracted" "$before" && continue
                split_file_four "$extracted"
            done < <(find "$DEST_DIR" -maxdepth 1 -type f)

            rm -f "$before"
            ;;
        *.gz)
            local out="${DEST_DIR}/$(basename "${archive%.gz}")"

            echo "[EXTRACT] $(basename "$archive")"

            gunzip -c "$archive" > "$out"

            echo "[DELETE] $(basename "$archive")"
            rm -f "$archive"

            split_file_four "$out"
            ;;
        *)
            echo "[WARN] Unknown archive format: $archive"
            exit 1
            ;;
    esac
}

echo "Destination: $DEST_DIR"
echo

for url in "${URLS[@]}"; do
    archive="$DEST_DIR/$(basename "$url")"
    tmp="${archive}.part"

    echo "[DOWNLOAD] $url"

    curl -L \
        --fail \
        --retry 3 \
        --retry-delay 5 \
        -o "$tmp" \
        "$url"

    mv "$tmp" "$archive"

    extract_and_process "$archive"
    echo
done

echo "Done."