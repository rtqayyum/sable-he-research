"""Datasets and client partitions for the FL case study."""

from __future__ import annotations

import os
from pathlib import Path

import numpy as np

STATS = {"mnist": (0.1307, 0.3081), "fmnist": (0.2860, 0.3530)}


def data_dir() -> Path:
    return Path(os.environ.get("SABLE_DATA_DIR", Path(__file__).resolve().parents[2] / "data"))


def download(name: str, root: Path | None = None) -> Path:
    """Download with torchvision and cache as a compact .npz (run once in the setup stage)."""
    import torchvision

    root = Path(root or data_dir())
    root.mkdir(parents=True, exist_ok=True)
    out = root / f"{name}.npz"
    if out.exists():
        return out
    cls = {"mnist": torchvision.datasets.MNIST, "fmnist": torchvision.datasets.FashionMNIST}[name]
    tr = cls(str(root / "raw"), train=True, download=True)
    te = cls(str(root / "raw"), train=False, download=True)
    tmp = out.with_suffix(".tmp.npz")
    np.savez_compressed(tmp, x_train=tr.data.numpy(), y_train=tr.targets.numpy(), x_test=te.data.numpy(), y_test=te.targets.numpy())
    os.replace(tmp, out)
    return out


def _synthetic(seed: int = 0, n_train: int = 6000, n_test: int = 1000) -> tuple[np.ndarray, ...]:
    """Learnable MNIST-shaped data for local smoke tests (no download needed)."""
    rng = np.random.default_rng(seed)
    protos = rng.normal(0, 1, (10, 28, 28))
    def make(n: int) -> tuple[np.ndarray, np.ndarray]:
        y = rng.integers(0, 10, n)
        x = protos[y] + rng.normal(0, 1.5, (n, 28, 28))
        return x.astype(np.float32), y.astype(np.int64)
    xtr, ytr = make(n_train)
    xte, yte = make(n_test)
    return xtr[:, None], ytr, xte[:, None], yte


def load(name: str) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Return (x_train, y_train, x_test, y_test) as float32 NCHW, normalized."""
    if name == "synthetic":
        return _synthetic()
    path = data_dir() / f"{name}.npz"
    if not path.exists():
        raise FileNotFoundError(f"{path} missing: run the setup stage (it downloads MNIST/Fashion-MNIST)")
    z = np.load(path)
    mean, std = STATS[name]
    def prep(x: np.ndarray) -> np.ndarray:
        return ((x.astype(np.float32) / 255.0 - mean) / std)[:, None]
    return prep(z["x_train"]), z["y_train"].astype(np.int64), prep(z["x_test"]), z["y_test"].astype(np.int64)


def partition(y: np.ndarray, clients: int, scheme: str, seed: int, min_size: int = 10) -> list[np.ndarray]:
    """Split sample indices across clients: 'iid' or 'dir<alpha>' (e.g. dir0.5)."""
    rng = np.random.default_rng(seed)
    n = len(y)
    if scheme == "iid":
        return [np.sort(p) for p in np.array_split(rng.permutation(n), clients)]
    if not scheme.startswith("dir"):
        raise ValueError(f"unknown partition {scheme!r}")
    alpha = float(scheme[3:])
    classes = np.unique(y)
    for _ in range(100):
        parts: list[list[int]] = [[] for _ in range(clients)]
        for c in classes:
            idx = rng.permutation(np.flatnonzero(y == c))
            props = rng.dirichlet(np.full(clients, alpha))
            cuts = (np.cumsum(props) * len(idx)).astype(int)[:-1]
            for k, chunk in enumerate(np.split(idx, cuts)):
                parts[k].extend(chunk.tolist())
        if min(len(p) for p in parts) >= min_size:
            return [np.sort(np.asarray(p, dtype=np.int64)) for p in parts]
    raise RuntimeError("could not draw a Dirichlet partition with the minimum client size")
