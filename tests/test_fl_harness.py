"""Guards for the FL case-study harness (skipped when torch is not installed)."""

import sys
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")
torch = pytest.importorskip("torch")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_set_vector_copies_and_local_training_leaves_global_vector_unchanged():
    from evaluation.fl import models

    m = models.make("lr", 0)
    w_global = models.get_vector(m)
    before = w_global.copy()
    models.set_vector(m, w_global)
    x = torch.randn(64, 1, 28, 28)
    y = torch.randint(0, 10, (64,))
    models.train_local(m, x, y, epochs=1, batch=16, lr=0.1, seed=0)
    assert np.array_equal(w_global, before), "local training modified the global weight vector"
    assert np.abs(models.get_vector(m) - w_global).max() > 0, "local training produced a zero update"


def test_fedavg_round_updates_are_nonzero_and_sable_equals_quantized_reference():
    from evaluation.fl.run import run_fl
    from evaluation.registry import _fl_cfg

    out = {}
    for method in ("plain", "sable"):
        cfg = _fl_cfg("synthetic", "lr", "iid", 3, 0, method, 2, "full")
        out[method] = run_fl(cfg)
    for method, r in out.items():
        for h in r["history"]:
            assert h["client_update_l2"] > 0, f"{method}: zero client updates"
            assert h["agg_l2"] > 0, f"{method}: zero aggregate"
    assert all(h["agg_max_abs_err_vs_reference"] == 0.0 for h in out["sable"]["history"])
    # plain (float) and SABLE (2^-17 fixed point) runs follow nearly the same path, but not bit-identical losses
    lp = [h["test_loss"] for h in out["plain"]["history"]]
    ls = [h["test_loss"] for h in out["sable"]["history"]]
    assert lp != ls
    assert max(abs(a - b) for a, b in zip(lp, ls)) < 1e-2
