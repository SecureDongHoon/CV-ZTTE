# CV-ZTTE local toolchain environment.
# Usage:  source env.sh
# All tools are installed user-local (no sudo). See docs/ENVIRONMENT.md.

export CVZTTE_ROOT="/home/secure_donghoon/personal_growth/security/CV-ZTTE"

# --- OpenSSL 3.5.8 (native ML-DSA) built from source ---
export CVZTTE_OPENSSL_HOME="$HOME/opt/openssl-3.5.8"

# --- Go 1.27.1 (gnark) ---
export GOROOT="$HOME/opt/go"
export GOPATH="$HOME/go"

# --- OpenFHE 1.5.1 (native CKKS/threshold FHE) built from source ---
export CVZTTE_OPENFHE_HOME="$HOME/opt/openfhe"

# --- PATH: local openssl first so `openssl` resolves to 3.5.8 ---
export PATH="$CVZTTE_OPENSSL_HOME/bin:$HOME/.local/bin:$GOROOT/bin:$GOPATH/bin:$PATH"

# --- Shared libs for the source-built OpenSSL + OpenFHE ---
export LD_LIBRARY_PATH="$CVZTTE_OPENSSL_HOME/lib64:$CVZTTE_OPENSSL_HOME/lib:$CVZTTE_OPENFHE_HOME/lib:${LD_LIBRARY_PATH:-}"

# --- Python virtualenv ---
if [ -f "$CVZTTE_ROOT/.venv/bin/activate" ]; then
  # shellcheck disable=SC1091
  . "$CVZTTE_ROOT/.venv/bin/activate"
fi
