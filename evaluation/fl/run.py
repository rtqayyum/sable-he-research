"""One federated-learning run with a chosen secure-aggregation backend."""

from __future__ import annotations

import time
from typing import Any

import numpy as np

from evaluation.aggregation import make_backend
from evaluation.common import stable_seed


def run_fl(cfg: dict[str, Any]) -> dict[str, Any]:
    import torch

    from evaluation.fl import data as fdata
    from evaluation.fl import models as fmodels

    torch.set_num_threads(int(cfg.get("threads", 1)))
    seed = int(cfg["seed"])
    rounds = int(cfg["rounds"])
    K = int(cfg["clients"])
    crypto = cfg.get("crypto", "full")  # full | sampled
    sample_rounds = int(cfg.get("sample_rounds", 2))
    eval_every = int(cfg.get("eval_every", 1))

    xtr, ytr, xte, yte = fdata.load(cfg["dataset"])
    parts = fdata.partition(ytr, K, cfg["partition"], stable_seed(seed, "partition"))
    Xtr, Ytr = torch.from_numpy(xtr), torch.from_numpy(ytr)
    Xte, Yte = torch.from_numpy(xte), torch.from_numpy(yte)
    sizes = np.array([len(p) for p in parts], dtype=np.float64)
    weights = sizes / sizes.sum()

    model = fmodels.make(cfg["model"], seed)
    w_global = fmodels.get_vector(model)
    d = int(w_global.size)
    backend = make_backend(cfg["method"], d, K, seed, **cfg.get("backend_opts", {}))
    setup = backend.setup()

    history: list[dict[str, Any]] = []
    last_measured: dict[str, Any] | None = None
    total_failures = 0
    t_run = time.perf_counter()
    for r in range(rounds):
        deltas, losses, train_t = [], [], []
        for c in range(K):
            fmodels.set_vector(model, w_global)
            t0 = time.perf_counter()
            losses.append(fmodels.train_local(model, Xtr[parts[c]], Ytr[parts[c]], int(cfg.get("local_epochs", 1)),
                                              int(cfg.get("batch", 32)), float(cfg.get("lr", 0.05)), stable_seed(seed, "sgd", r, c)))
            train_t.append(time.perf_counter() - t0)
            deltas.append(fmodels.get_vector(model) - w_global)
        if crypto == "full" or r < sample_rounds:
            agg, met = backend.run_round(r, deltas, weights)
            met = dict(met, measured=True)
            last_measured = met
            total_failures += int(met.get("coord_failures", 0))
        else:
            agg = backend.reference(deltas, weights)
            met = dict(last_measured or {}, measured=False)
        w_global = (w_global + agg.astype(np.float32)).astype(np.float32)
        row: dict[str, Any] = {"round": r + 1, "train_loss": float(np.average(losses, weights=weights)),
                               "client_train_s": float(np.mean(train_t))}
        row.update({k: v for k, v in met.items() if not isinstance(v, (list, dict))})
        if (r + 1) % eval_every == 0 or r == rounds - 1:
            fmodels.set_vector(model, w_global)
            acc, loss = fmodels.evaluate(model, Xte, Yte)
            row.update(test_acc=acc, test_loss=loss)
        history.append(row)

    final = history[-1]
    measured = [h for h in history if h.get("measured")]
    def mean(key: str) -> float:
        vals = [h[key] for h in measured if key in h]
        return float(np.mean(vals)) if vals else float("nan")

    return {
        "config": cfg,
        "backend": backend.describe(),
        "setup": setup,
        "d": d,
        "client_sizes": sizes.astype(int).tolist(),
        "final_test_acc": final.get("test_acc"),
        "best_test_acc": max(h.get("test_acc", 0.0) for h in history),
        "total_coord_failures": total_failures,
        "measured_rounds": len(measured),
        "mean_upload_bytes_client": mean("upload_bytes_client"),
        "mean_client_encrypt_s": mean("client_encrypt_s"),
        "mean_server_aggregate_s": mean("server_aggregate_s"),
        "mean_decrypt_s": mean("decrypt_s"),
        "mean_client_train_s": float(np.mean([h["client_train_s"] for h in history])),
        "wall_s": time.perf_counter() - t_run,
        "history": history,
    }
