#!/bin/bash
# Create the Python 3.11 environment for SABLE-HE experiments (runs inside the setup Slurm job).
# Uses uv (installed into ~/.local if missing) so the HPC system Python version does not matter.
set -euo pipefail
PROJECT="$1"
CODE="$(cd "$(dirname "$0")/../.." && pwd)"
VENV="$PROJECT/work/venv"
export UV_CACHE_DIR="$PROJECT/work/uv-cache"
export UV_PYTHON_INSTALL_DIR="$PROJECT/work/python"
export PATH="$HOME/.local/bin:$PATH"
REQ="$CODE/scripts/hpc/requirements-hpc.txt"

echo "[setup] system python: $(python3 --version 2>&1 || echo none)"
if ! command -v uv >/dev/null 2>&1; then
  echo "[setup] installing uv into ~/.local"
  python3 -m pip install --user --quiet uv 2>/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi
uv --version

if [ ! -x "$VENV/bin/python" ]; then
  uv venv --python 3.11 "$VENV"
fi
"$VENV/bin/python" --version

# CPU-only torch from the PyTorch index when reachable; otherwise PyPI.
if uv pip install --python "$VENV/bin/python" -r "$REQ" \
     --index-url https://pypi.org/simple --extra-index-url https://download.pytorch.org/whl/cpu \
     --index-strategy unsafe-best-match; then
  echo "[setup] installed with the CPU torch index"
else
  echo "[setup] PyTorch CPU index unreachable; retrying from PyPI only"
  uv pip install --python "$VENV/bin/python" -r "$REQ" --index-url https://pypi.org/simple
fi
uv pip freeze --python "$VENV/bin/python" > "$PROJECT/work/venv-freeze.txt"
echo "[setup] environment ready: $VENV"
