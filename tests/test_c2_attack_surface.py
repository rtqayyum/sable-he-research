from sable.c2_attack_surface import c2_attack_report, c2_public_sample_profile
from sable.params import PRESETS


def test_c2_public_sample_profile_counts():
    params = PRESETS["c2_toy_clean"]
    profile = c2_public_sample_profile(params)
    assert profile.dictionary_entries == 6 * (7**2 - 1) + (7**1 - 1)
    assert profile.public_clpn_rows == profile.dictionary_entries * params.m_c
    assert profile.within_entry_difference_rows > profile.public_clpn_rows
    assert profile.cross_entry_difference_rows > 0
    assert profile.seeded_storage_reduction_factor_proxy > 1.0


def test_c2_attack_report_has_cross_entry_surface():
    report = c2_attack_report(PRESETS["c2_toy_clean"], target_bits=64)
    names = {line["name"] for line in report["attack_lines"]}
    assert "cross-entry clean-subset solving" in names
    assert "seeded-storage does not reduce samples" in names
    assert report["profile"]["dictionary_entries"] > 0
