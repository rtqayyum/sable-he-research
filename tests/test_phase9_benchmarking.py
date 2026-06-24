from pathlib import Path

from sable import benchmarking


def test_benchmark_workloads_present():
    names = {w.name for w in benchmarking.workloads()}
    assert {"add_scalar", "mul_scalar", "fedavg_3x3"}.issubset(names)


def test_baseline_specs_present():
    names = {b.name for b in benchmarking.baseline_specs()}
    assert {"openfhe", "microsoft-seal", "tfhe-rs", "concrete"}.issubset(names)


def test_run_one_sable_workload():
    from sable.params import PRESETS
    result = benchmarking.run_sable_workload(
        benchmarking.workload_by_name("add_scalar"),
        PRESETS["c7_standard_toy_clean"],
        repetitions=1,
    )
    assert result.ok
    assert result.timings_ms["keygen"].count == 1


def test_write_benchmark_package(tmp_path: Path):
    paths = benchmarking.write_benchmark_package(tmp_path, repetitions=1, selected_workloads=["add_scalar"])
    assert Path(paths["suite_json"]).exists()
    assert Path(paths["suite_csv"]).exists()
    assert Path(paths["external_template"]).exists()


def test_external_template_load(tmp_path: Path):
    p = tmp_path / "external.json"
    benchmarking.write_external_result_template(p)
    assert p.exists()
    # template values are null, so loading should return no measured rows
    assert benchmarking.load_external_results([p]) == []
