"""Shared helpers for the SABLE-HE experiment harness."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import socket
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))


def stable_seed(*parts: Any) -> int:
    """Deterministic 63-bit seed from arbitrary parts (independent of PYTHONHASHSEED)."""
    h = hashlib.sha256("|".join(map(str, parts)).encode()).digest()
    return int.from_bytes(h[:8], "big") & ((1 << 63) - 1)


def json_default(o: Any) -> Any:
    try:
        import numpy as np

        if isinstance(o, np.integer):
            return int(o)
        if isinstance(o, np.floating):
            return float(o)
        if isinstance(o, np.bool_):
            return bool(o)
        if isinstance(o, np.ndarray):
            return o.tolist()
    except ImportError:  # pragma: no cover
        pass
    if isinstance(o, Path):
        return str(o)
    if hasattr(o, "to_jsonable"):
        return o.to_jsonable()
    raise TypeError(f"not JSON serializable: {type(o)!r}")


def _clean(o: Any) -> Any:
    if isinstance(o, float):
        if math.isnan(o):
            return "nan"
        if math.isinf(o):
            return "inf" if o > 0 else "-inf"
        return o
    if isinstance(o, dict):
        return {str(k): _clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_clean(v) for v in o]
    return o


def atomic_write_json(path: Path | str, obj: Any) -> None:
    """Write JSON to a temporary file and rename it, so readers never see partial files."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    text = json.dumps(_clean(json.loads(json.dumps(obj, default=json_default))), indent=2, sort_keys=True)
    tmp.write_text(text + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Path | str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


@contextmanager
def timed() -> Iterator[dict[str, float]]:
    box: dict[str, float] = {}
    t0 = time.perf_counter()
    try:
        yield box
    finally:
        box["seconds"] = time.perf_counter() - t0


def package_versions() -> dict[str, str]:
    out: dict[str, str] = {"python": sys.version.split()[0]}
    for name in ["numpy", "scipy", "torch", "torchvision", "tenseal", "phe", "gmpy2", "matplotlib", "pandas"]:
        try:
            mod = __import__(name)
            out[name] = getattr(mod, "__version__", "installed")
        except Exception as exc:  # noqa: BLE001
            out[name] = f"unavailable ({type(exc).__name__})"
    try:
        from sable.version import __version__ as sv

        out["sable"] = sv
    except Exception:  # noqa: BLE001
        out["sable"] = "unavailable"
    return out


def env_info() -> dict[str, Any]:
    slurm = {k: v for k, v in os.environ.items() if k.startswith("SLURM_")}
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "slurm": slurm,
        "packages": package_versions(),
        "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def peak_rss_gb() -> float:
    try:
        import resource

        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1e6
    except Exception:  # noqa: BLE001
        return float("nan")
