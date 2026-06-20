from sable.attack_estimator import estimate_instance, estimate_params, LPNInstance, log2_binom
from sable.params import PRESETS


def test_log2_binom_basic():
    assert abs(log2_binom(4, 2) - 2.5849625007) < 1e-6


def test_zero_noise_is_flagged():
    inst = LPNInstance(name="z", q=127, dimension=4, samples=8, eta=0.0, row_weight=2)
    est = estimate_instance(inst)
    names = [a.name for a in est.attacks]
    assert "zero_noise_linear_solve" in names
    assert est.best_feasible_log2_work is not None


def test_preset_estimate_has_instances():
    est = estimate_params(PRESETS["toy_noisy"])
    assert est["instances"]
    assert "screening_warning" in est


def test_clean_subset_screen_catches_low_noise():
    inst = LPNInstance(name="low_noise", q=127, dimension=24, samples=625, eta=0.002)
    est = estimate_instance(inst)
    names = [a.name for a in est.attacks]
    assert "clean_subset_linear_solve" in names
    assert est.best_feasible_log2_work is not None
    assert est.best_feasible_log2_work < 32
