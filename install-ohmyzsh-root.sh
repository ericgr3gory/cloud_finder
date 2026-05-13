#!/usr/bin/env bash
set -euo pipefail

TARGET_USER="${1:-root}"
TARGET_HOME="$(eval echo "~${TARGET_USER}")"

if [[ ! -d "$TARGET_HOME" ]]; then
    echo "User home not found: $TARGET_HOME"
    exit 1
fi

echo "[*] Installing dependencies..."
apt update
apt install -y zsh git curl

if ! id "$TARGET_USER" >/dev/null 2>&1; then
    echo "User does not exist: $TARGET_USER"
    exit 1
fi

echo "[*] Installing Oh My Zsh for $TARGET_USER..."

if [[ ! -d "$TARGET_HOME/.oh-my-zsh" ]]; then
    export HOME="$TARGET_HOME"
    export RUNZSH=no
    export CHSH=no

    curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh \
        -o /tmp/ohmyzsh-install.sh

    if [[ "$TARGET_USER" == "root" ]]; then
        bash /tmp/ohmyzsh-install.sh
    else
        su - "$TARGET_USER" -c "HOME=$TARGET_HOME RUNZSH=no CHSH=no bash /tmp/ohmyzsh-install.sh"
    fi
fi

CUSTOM="$TARGET_HOME/.oh-my-zsh/custom/plugins"

mkdir -p "$CUSTOM"

if [[ ! -d "$CUSTOM/zsh-autosuggestions" ]]; then
    git clone \
        https://github.com/zsh-users/zsh-autosuggestions \
        "$CUSTOM/zsh-autosuggestions"
fi

if [[ ! -d "$CUSTOM/zsh-syntax-highlighting" ]]; then
    git clone \
        https://github.com/zsh-users/zsh-syntax-highlighting.git \
        "$CUSTOM/zsh-syntax-highlighting"
fi

cat > "$TARGET_HOME/.zshrc" <<'EOF'
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="robbyrussell"

plugins=(
  git
  zsh-autosuggestions
  zsh-syntax-highlighting
)

source $ZSH/oh-my-zsh.sh
EOF

chown -R "$TARGET_USER:$TARGET_USER" \
    "$TARGET_HOME/.oh-my-zsh" \
    "$TARGET_HOME/.zshrc"

chsh -s /usr/bin/zsh "$TARGET_USER" || true

echo "[+] Done for $TARGET_USER"
echo "[+] Run: exec zsh"