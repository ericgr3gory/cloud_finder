#!/usr/bin/env bash
set -euo pipefail

WORKER_USER="hashcat"
WORKER_HOME="/home/${WORKER_USER}"
REPO_DIR="${WORKER_HOME}/python-hashes"
SUPERVISOR_DIR="/etc/supervisor/conf.d"
LOG_DIR="${WORKER_HOME}/.hashcat/logs"

PYTHON="${REPO_DIR}/.venv/bin/python"
CONSUMER="${REPO_DIR}/gpu-consumer.py"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Missing required command: $1"
        exit 1
    }
}

require_cmd nvidia-smi
require_cmd supervisorctl

if [[ ! -x "$PYTHON" ]]; then
    echo "Python venv not found: $PYTHON"
    exit 1
fi

if [[ ! -f "$CONSUMER" ]]; then
    echo "Consumer not found: $CONSUMER"
    exit 1
fi

mkdir -p "$LOG_DIR"
chown -R "${WORKER_USER}:${WORKER_USER}" "$LOG_DIR"

echo "[*] Removing old generated GPU supervisor configs..."
rm -f "${SUPERVISOR_DIR}"/hashkitty-gpu-*.conf

GPU_COUNT=0

while read -r UUID; do
    [[ -z "$UUID" ]] && continue

    GPU_COUNT=$((GPU_COUNT + 1))

    SHORT="${UUID#GPU-}"
    NAME="hashkitty-gpu-${GPU_COUNT}"
    CONF="${SUPERVISOR_DIR}/${NAME}.conf"

    echo "[*] Creating supervisor config for GPU ${GPU_COUNT}: ${UUID}"

    cat > "$CONF" <<EOF
[program:${NAME}]
command=${PYTHON} ${CONSUMER}
directory=${REPO_DIR}
user=${WORKER_USER}
autostart=true
autorestart=true
startsecs=5
stopasgroup=true
killasgroup=true
stdout_logfile=${LOG_DIR}/${NAME}.log
stderr_logfile=${LOG_DIR}/${NAME}.err.log
stdout_logfile_maxbytes=20MB
stderr_logfile_maxbytes=20MB
stdout_logfile_backups=3
stderr_logfile_backups=3
environment=HOME="${WORKER_HOME}",CUDA_VISIBLE_DEVICES="${UUID}"
EOF

done < <(nvidia-smi --query-gpu=uuid --format=csv,noheader)

if [[ "$GPU_COUNT" -eq 0 ]]; then
    echo "No NVIDIA GPUs detected."
    exit 1
fi

echo "[*] Found ${GPU_COUNT} GPU(s)"

echo "[*] Reloading supervisor..."
supervisorctl reread
supervisorctl update

echo "[*] Current supervisor status:"
supervisorctl status

echo "[+] Done."