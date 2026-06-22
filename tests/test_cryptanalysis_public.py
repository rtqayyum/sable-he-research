from __future__ import annotations

import json
from pathlib import Path

from sable.cryptanalysis import (
    attack_surface_report,
    challenge_info,
    known_answer_vector,
    red_team_template,
    write_challenge_bundle,
)
from sable.params import PRESETS


def test_challenge_info_shape():
    info = challenge_info()
    assert info["schema"] == "sable-cryptanalysis-bundle-v1"
    assert "sparse q-ary LPN" in " ".join(info["assumptions_to_review"])


def test_known_answer_vector_passes():
    vector = known_answer_vector()
    assert vector.status == "pass"
    assert vector.results["mul_x_y"] == (3 * 5) % vector.q


def test_attack_surface_report_contains_screens():
    report = attack_surface_report(PRESETS["c7_standard_toy_noisy"], target_bits=64)
    assert report["schema"] == "sable-attack-surface-report-v1"
    assert report["surface_summary"]["expansion_key_rows"] > 0
    assert report["attack_lines"]


def test_red_team_template_mentions_impact():
    assert "## Impact" in red_team_template()


def test_write_challenge_bundle(tmp_path: Path):
    manifest = write_challenge_bundle(tmp_path, presets=["c7_standard_toy_clean"], target_bits=32)
    assert "challenge_info.json" in manifest["files"]
    assert (tmp_path / "vectors" / "sable_known_answer_vector.json").exists()
    report_files = list((tmp_path / "reports").glob("*.json"))
    assert len(report_files) == 1
    payload = json.loads(report_files[0].read_text())
    assert payload["schema"] == "sable-attack-surface-report-v1"
