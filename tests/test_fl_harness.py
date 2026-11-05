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
    lp = [h["test_loss"] for h in out["plain"]["history"]]
    ls = [h["test_loss"] for h in out["sable"]["history"]]
    assert max(abs(a - b) for a, b in zip(lp, ls)) < 1e-4


def test_fixed_point_grids_keep_small_updates_with_many_clients():
    """With K=1000 the weighted per-client values are ~1e-7; every exact backend must still resolve them."""
    from evaluation.aggregation import float_reference, make_backend

    from evaluation.aggregation import quantized_reference

    d, K = 2000, 1000
    rng = np.random.default_rng(0)
    common = rng.normal(0, 6e-4, d)  # clients follow roughly the same gradient direction
    deltas = [(common + rng.normal(0, 3e-4, d)).astype(np.float32) for _ in range(K)]
    w = np.full(K, 1.0 / K)
    f = float_reference(deltas, w)
    old = np.linalg.norm(quantized_reference(deltas, w, 2**17) - f) / np.linalg.norm(f)
    assert old > 0.5, "the old shared 2^-17 grid should lose most of this signal"
    for method in ("sable", "lwe", "secagg", "bfv"):
        b = make_backend(method, d, K, 1)
        rel = np.linalg.norm(b.reference(deltas, w) - f) / np.linalg.norm(f)
        assert rel < 1e-4, f"{method}: fixed-point grid too coarse (relative error {rel:.2e})"
        assert b.scale >= 2**27, method
