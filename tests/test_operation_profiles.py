from sable.operation_profiles import PROFILES, compare_all, compare_operation, support_table_as_dicts
from sable.params import PRESETS


def test_support_table_contains_native_and_boundary_operations():
    rows = support_table_as_dicts()
    ops = {row["operation"]: row for row in rows}
    assert ops["addition"]["native"] is True
    assert ops["multiplication"]["native"] is True
    assert ops["integer comparison/order"]["native"] is False
    assert ops["field inverse"]["native"] is False


def test_compare_operation_has_existing_method_proxies():
    comp = compare_operation(PRESETS["c4_projective_toy_clean"], PROFILES["bool_xor"])
    assert comp["sable_c4"]["multiplicative_depth"] == 1
    assert comp["existing_method_proxies"]["TFHE_FHEW"]["gate_or_bootstrap_proxy"] == 1
    assert comp["existing_method_proxies"]["BFV_BGV"]["ciphertext_multiplications"] == 1


def test_compare_all_runs():
    rows = compare_all(PRESETS["c4_projective_toy_clean"])
    assert len(rows) >= 8
    assert {r["operation"]["name"] for r in rows} >= {"add", "mul", "bool_and", "poly2"}
