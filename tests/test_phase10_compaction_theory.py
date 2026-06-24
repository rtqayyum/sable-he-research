from pathlib import Path

from sable import compaction_theory as ct


def test_phase10_info():
    info = ct.compaction_theory_info()
    assert info["version"] >= "0.11.0"
    assert "mask" in info["main_contribution"]


def test_projective_count():
    fam = ct.projective_family(q=3, block_width=2)
    assert fam.entries_per_block == (3**2 - 1) // (3 - 1)


def test_coordinate_no_sparse_kernel_relation():
    fam = ct.coordinate_family(q=31, block_width=4)
    screen = ct.sparse_kernel_screen(fam, max_weight=4)
    assert screen.minimum_relation_weight is None
    assert screen.status.startswith("no-relation")


def test_projective_relation_found():
    fam = ct.projective_family(q=3, block_width=2)
    screen = ct.sparse_kernel_screen(fam, max_weight=3)
    assert screen.minimum_relation_weight is not None
    assert screen.minimum_relation_weight <= 3


def test_analyze_coordinate_role():
    report = ct.analyze_compaction_family("coordinate", q=31, n=128, block_width=1, m_c=32)
    assert report.suggested_role == "main-scheme-default"
    assert report.total_public_entries == 129


def test_compaction_package(tmp_path: Path):
    manifest = ct.write_compaction_package(tmp_path / "pkg", q=5, n=16, block_width=2, m_c=8)
    assert manifest["status"].startswith("review")
    assert (tmp_path / "pkg" / "compaction_family_reports.json").exists()
