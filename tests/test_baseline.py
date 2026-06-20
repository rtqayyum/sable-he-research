from sable.baseline import PROFILES, compare_profile
from sable.params import PRESETS


def test_baseline_comparison_runs():
    comp = compare_profile(PRESETS["toy_depth2"], PROFILES["degree4_tree"])
    assert comp.sable["sparse_field_mul_add_proxy"] > 0
    assert comp.tfhe_proxy["bootstrapped_gate_count"] == 3
