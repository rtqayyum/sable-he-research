"""Phase 9 benchmark-comparison framework for SABLE-HE.

The module measures SABLE-HE's Python research implementation on common
low-depth workloads and writes reproducible templates for external FHE
baselines. It deliberately separates measured SABLE timings from external
baseline placeholders: OpenFHE, SEAL, TFHE-rs, Concrete, and Lattigo must be
run in their own reviewed environments and imported through the JSON schema
used here.
"""

from __future__ import annotations

import csv
import json
import math
import platform
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import operations as ops
from .fl import EncryptedFLAggregator
from .params import PRESETS, SableParams
from .sable import compact_c7, decrypt_c7, encrypt, expand, keygen_c7
from .version import __version__


@dataclass(frozen=True)
class BenchmarkWorkload:
    """Description of a benchmark workload."""

    name: str
    family: str
    operation: str
    inputs: tuple[int, ...]
    description: str
    multiplicative_depth: int = 0
    additions: int = 0
    multiplications: int = 0
    boolean_gates: int = 0
    vector_length: int = 1
    fl_clients: int = 0


@dataclass(frozen=True)
class BaselineSpec:
    """External baseline that should be run independently."""

    name: str
    family: str
    schemes: tuple[str, ...]
    best_for: str
    workload_match: tuple[str, ...]
    command_template: str
    install_hint: str
    result_schema: str = "sable-benchmark-result-v1"


@dataclass
class TimingStats:
    """Simple timing summary."""

    count: int
    mean_ms: float
    median_ms: float
    min_ms: float
    max_ms: float
    stdev_ms: float


@dataclass
class SableBenchmarkResult:
    """Measured SABLE result for one workload."""

    schema: str
    package: str
    version: str
    backend: str
    preset: str
    workload: str
    workload_family: str
    q: int
    n: int
    k: int
    repetitions: int
    timings_ms: dict[str, TimingStats]
    observed: Any
    expected: Any
    ok: bool
    notes: list[str] = field(default_factory=list)


@dataclass
class BenchmarkSuiteResult:
    """Collection of measured SABLE benchmark results."""

    schema: str
    package: str
    version: str
    backend: str
    preset: str
    platform: dict[str, str]
    results: list[SableBenchmarkResult]
    external_baselines: list[BaselineSpec]
    warning: str


@dataclass
class ExternalResult:
    """Normalized external-baseline result entry."""

    backend: str
    scheme: str
    workload: str
    metric: str
    value: float
    unit: str
    source_file: str | None = None
    notes: str | None = None


SCHEMA_RESULT = "sable-benchmark-result-v1"
SCHEMA_SUITE = "sable-benchmark-suite-v1"


def benchmark_info() -> dict[str, Any]:
    """Return machine-readable Phase 9 benchmark scope."""
    return {
        "package": "sable-he-research",
        "version": __version__,
        "phase": "Phase 9 benchmark comparison framework",
        "status": "internal top-venue strengthening; measured SABLE plus external baseline harnesses",
        "measured_in_package": [
            "SABLE-HE Python research implementation",
            "encrypted arithmetic workloads",
            "encrypted FedAvg-style weighted averaging",
        ],
        "external_baselines": [asdict(spec) for spec in baseline_specs()],
        "non_goals": [
            "fabricating external FHE wall-clock numbers",
            "claiming performance superiority without identical-machine measurements",
            "certifying SABLE-HE parameters",
        ],
    }


def benchmark_platform() -> dict[str, str]:
    """Return reproducibility metadata for the local Python benchmark run."""
    return {
        "python": sys.version.replace("\n", " "),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
        "system": platform.system(),
    }


def workloads() -> list[BenchmarkWorkload]:
    """Return the canonical Phase 9 workload set."""
    return [
        BenchmarkWorkload(
            name="add_scalar",
            family="exact-arithmetic",
            operation="add",
            inputs=(12, 20),
            additions=1,
            description="Encrypted addition of two scalar field elements.",
        ),
        BenchmarkWorkload(
            name="mul_scalar",
            family="exact-arithmetic",
            operation="mul",
            inputs=(3, 5),
            multiplicative_depth=1,
            multiplications=1,
            description="Encrypted multiplication of two scalar field elements.",
        ),
        BenchmarkWorkload(
            name="square_scalar",
            family="exact-arithmetic",
            operation="square",
            inputs=(9,),
            multiplicative_depth=1,
            multiplications=1,
            description="Encrypted squaring of one scalar field element.",
        ),
        BenchmarkWorkload(
            name="boolean_and",
            family="boolean",
            operation="and",
            inputs=(1, 0),
            multiplicative_depth=1,
            multiplications=1,
            boolean_gates=1,
            description="Boolean AND encoded over F_q.",
        ),
        BenchmarkWorkload(
            name="boolean_xor",
            family="boolean",
            operation="xor",
            inputs=(1, 0),
            multiplicative_depth=1,
            additions=2,
            multiplications=1,
            boolean_gates=1,
            description="Boolean XOR encoded as x+y-2xy over F_q.",
        ),
        BenchmarkWorkload(
            name="dot4",
            family="vector-arithmetic",
            operation="dot4",
            inputs=(1, 2, 3, 4, 5, 6, 7, 8),
            multiplicative_depth=1,
            additions=3,
            multiplications=4,
            vector_length=4,
            description="Encrypted dot product of two length-4 vectors.",
        ),
        BenchmarkWorkload(
            name="quadratic4",
            family="low-degree-polynomial",
            operation="quadratic4",
            inputs=(2, 3, 4, 5),
            multiplicative_depth=1,
            additions=3,
            multiplications=2,
            vector_length=4,
            description="Low-degree polynomial x1*x2 + x3*x4 + x1 + x4.",
        ),
        BenchmarkWorkload(
            name="fedavg_3x3",
            family="federated-learning",
            operation="fedavg",
            inputs=(0,),
            additions=6,
            vector_length=3,
            fl_clients=3,
            description="Encrypted FedAvg over three clients and three weights.",
        ),
    ]


def workload_by_name(name: str) -> BenchmarkWorkload:
    """Return a named workload or raise ValueError."""
    for workload in workloads():
        if workload.name == name:
            return workload
    names = ", ".join(w.name for w in workloads())
    raise ValueError(f"unknown workload {name!r}; available: {names}")


def baseline_specs() -> list[BaselineSpec]:
    """Return external FHE baseline specifications."""
    return [
        BaselineSpec(
            name="openfhe",
            family="lattice-fhe",
            schemes=("BFV", "BGV", "CKKS", "FHEW", "TFHE-like"),
            best_for="exact integer arithmetic, approximate arithmetic, Boolean/function evaluation",
            workload_match=("add_scalar", "mul_scalar", "dot4", "quadratic4", "boolean_and", "boolean_xor"),
            command_template="./run_openfhe_benchmarks --json {output}",
            install_hint="Build OpenFHE locally and run matching BFV/BGV/CKKS/FHEW/TFHE workloads.",
        ),
        BaselineSpec(
            name="microsoft-seal",
            family="lattice-fhe",
            schemes=("BFV", "BGV", "CKKS"),
            best_for="exact modular/integer arithmetic and approximate arithmetic",
            workload_match=("add_scalar", "mul_scalar", "dot4", "quadratic4"),
            command_template="./run_seal_benchmarks --json {output}",
            install_hint="Build Microsoft SEAL examples or a custom SEAL benchmark driver.",
        ),
        BaselineSpec(
            name="tfhe-rs",
            family="torus-fhe",
            schemes=("TFHE",),
            best_for="Boolean, short-integer, and integer circuits",
            workload_match=("boolean_and", "boolean_xor", "add_scalar", "mul_scalar"),
            command_template="cargo run --release --bin sable_tfhe_rs_bench -- --json {output}",
            install_hint="Install Rust and TFHE-rs; run identical Boolean/integer workloads.",
        ),
        BaselineSpec(
            name="concrete",
            family="tfhe-compiler",
            schemes=("TFHE compiler",),
            best_for="compiled FHE programs from Python-like functions",
            workload_match=("add_scalar", "mul_scalar", "dot4", "boolean_and", "boolean_xor"),
            command_template="python concrete_benchmarks.py --json {output}",
            install_hint="Install Concrete and compile identical FHE functions for measurement.",
        ),
        BaselineSpec(
            name="lattigo",
            family="lattice-fhe",
            schemes=("BFV/BGV-style", "CKKS"),
            best_for="Go-based exact and approximate lattice-FHE baselines",
            workload_match=("add_scalar", "mul_scalar", "dot4", "quadratic4"),
            command_template="go test ./benchmarks -bench . -json > {output}",
            install_hint="Install Go and Lattigo; run matching exact/approximate workloads.",
        ),
    ]


def baseline_protocol_markdown() -> str:
    """Return a Markdown protocol for external benchmark comparison."""
    lines = [
        "# SABLE-HE Phase 9 external FHE benchmark protocol",
        "",
        "Run SABLE and all external FHE libraries on the same machine, with the same CPU governor, no background workloads, and repeated trials.",
        "",
        "## Required metrics",
        "",
        "- key-generation time in milliseconds",
        "- encryption time in milliseconds",
        "- evaluation time in milliseconds",
        "- compaction/decryption time in milliseconds, where applicable",
        "- public/evaluation key size in bytes",
        "- ciphertext size in bytes",
        "- peak memory if available",
        "- security/parameter description",
        "",
        "## Workloads",
    ]
    for workload in workloads():
        lines.append(f"- `{workload.name}` ({workload.family}): {workload.description}")
    lines.extend(["", "## External baselines", ""])
    for spec in baseline_specs():
        lines.append(f"### {spec.name}")
        lines.append(f"- schemes: {', '.join(spec.schemes)}")
        lines.append(f"- best for: {spec.best_for}")
        lines.append(f"- workloads: {', '.join(spec.workload_match)}")
        lines.append(f"- command template: `{spec.command_template}`")
        lines.append(f"- install hint: {spec.install_hint}")
        lines.append("")
    lines.extend([
        "## JSON result schema",
        "",
        "Each external result file should contain either a list of records or an object with a `results` list.",
        "Each record should have: `backend`, `scheme`, `workload`, `metric`, `value`, `unit`, and optional `notes`.",
        "",
        "SABLE-HE comparison papers must not mix measured SABLE results with fabricated external results.",
    ])
    return "\n".join(lines) + "\n"


def _timing_stats(values: Iterable[float]) -> TimingStats:
    vals = [v * 1000.0 for v in values]
    if not vals:
        return TimingStats(0, 0.0, 0.0, 0.0, 0.0, 0.0)
    return TimingStats(
        count=len(vals),
        mean_ms=statistics.fmean(vals),
        median_ms=statistics.median(vals),
        min_ms=min(vals),
        max_ms=max(vals),
        stdev_ms=statistics.stdev(vals) if len(vals) > 1 else 0.0,
    )


def _encrypt_expand(kp: Any, value: int, seed: int) -> Any:
    return expand(kp, encrypt(kp, value, seed=seed))


def _decrypt(kp: Any, ct: Any) -> int:
    return decrypt_c7(kp, compact_c7(kp, ct))


def _apply_scalar_workload(workload: BenchmarkWorkload, kp: Any, q: int, seed: int) -> tuple[Any, int]:
    op = workload.operation
    inputs = [x % q for x in workload.inputs]
    if op == "add":
        x = _encrypt_expand(kp, inputs[0], seed + 1)
        y = _encrypt_expand(kp, inputs[1], seed + 2)
        return ops.add(x, y), (inputs[0] + inputs[1]) % q
    if op == "mul":
        x = _encrypt_expand(kp, inputs[0], seed + 1)
        y = _encrypt_expand(kp, inputs[1], seed + 2)
        return ops.mul(x, y), (inputs[0] * inputs[1]) % q
    if op == "square":
        x = _encrypt_expand(kp, inputs[0], seed + 1)
        return ops.square(x), (inputs[0] * inputs[0]) % q
    if op == "and":
        x = _encrypt_expand(kp, inputs[0], seed + 1)
        y = _encrypt_expand(kp, inputs[1], seed + 2)
        return ops.gate_and(x, y), (inputs[0] * inputs[1]) % q
    if op == "xor":
        x = _encrypt_expand(kp, inputs[0], seed + 1)
        y = _encrypt_expand(kp, inputs[1], seed + 2)
        return ops.gate_xor(x, y), (inputs[0] + inputs[1] - 2 * inputs[0] * inputs[1]) % q
    if op == "dot4":
        a = inputs[:4]
        b = inputs[4:8]
        acc = None
        for i, (av, bv) in enumerate(zip(a, b)):
            x = _encrypt_expand(kp, av, seed + 10 + i)
            y = _encrypt_expand(kp, bv, seed + 20 + i)
            prod = ops.mul(x, y)
            acc = prod if acc is None else ops.add(acc, prod)
        assert acc is not None
        return acc, sum((av * bv for av, bv in zip(a, b))) % q
    if op == "quadratic4":
        vals = inputs[:4]
        cts = [_encrypt_expand(kp, v, seed + 100 + i) for i, v in enumerate(vals)]
        term1 = ops.mul(cts[0], cts[1])
        term2 = ops.mul(cts[2], cts[3])
        out = ops.add(ops.add(term1, term2), ops.add(cts[0], cts[3]))
        expected = (vals[0] * vals[1] + vals[2] * vals[3] + vals[0] + vals[3]) % q
        return out, expected
    raise ValueError(f"unsupported scalar workload operation: {op}")


def run_sable_workload(
    workload: BenchmarkWorkload,
    params: SableParams,
    repetitions: int = 3,
    seed: int = 12345,
) -> SableBenchmarkResult:
    """Measure SABLE for one workload using deterministic seeds."""
    keygen_times: list[float] = []
    encrypt_eval_times: list[float] = []
    decrypt_times: list[float] = []
    observed_values: list[Any] = []
    expected_values: list[Any] = []
    ok = True

    for rep in range(repetitions):
        rep_seed = seed + 1000 * rep
        t0 = time.perf_counter()
        kp = keygen_c7(params, seed=rep_seed, mode="coordinate")
        keygen_times.append(time.perf_counter() - t0)

        if workload.operation == "fedavg":
            client_models = [
                [0.12, -0.34, 1.20],
                [0.10, -0.30, 1.25],
                [0.20, -0.40, 1.10],
            ]
            sample_counts = [80, 20, 100]
            agg = EncryptedFLAggregator(kp, scale=1000, seed=rep_seed + 7)
            t1 = time.perf_counter()
            encrypted = [agg.encrypt_model(model, seed=rep_seed + 100 + i) for i, model in enumerate(client_models)]
            encrypted_avg = agg.fedavg(encrypted, sample_counts)
            encrypt_eval_times.append(time.perf_counter() - t1)
            t2 = time.perf_counter()
            observed = agg.decrypt_model(encrypted_avg)
            decrypt_times.append(time.perf_counter() - t2)
            total = sum(sample_counts)
            expected = [
                sum(sample_counts[i] * client_models[i][j] for i in range(len(client_models))) / total
                for j in range(3)
            ]
            observed_values.append(observed)
            expected_values.append(expected)
            ok = ok and all(abs(float(o) - float(e)) <= 1e-9 for o, e in zip(observed, expected))
        else:
            t1 = time.perf_counter()
            result_ct, expected = _apply_scalar_workload(workload, kp, params.q, rep_seed)
            encrypt_eval_times.append(time.perf_counter() - t1)
            t2 = time.perf_counter()
            observed = _decrypt(kp, result_ct)
            decrypt_times.append(time.perf_counter() - t2)
            observed_values.append(observed)
            expected_values.append(expected)
            ok = ok and observed == expected

    return SableBenchmarkResult(
        schema=SCHEMA_RESULT,
        package="sable-he-research",
        version=__version__,
        backend="sable-python-reference",
        preset=params.name,
        workload=workload.name,
        workload_family=workload.family,
        q=params.q,
        n=params.n,
        k=params.k,
        repetitions=repetitions,
        timings_ms={
            "keygen": _timing_stats(keygen_times),
            "encrypt_expand_eval_or_fl_aggregate": _timing_stats(encrypt_eval_times),
            "compact_decrypt_or_fl_decrypt": _timing_stats(decrypt_times),
        },
        observed=observed_values[-1] if observed_values else None,
        expected=expected_values[-1] if expected_values else None,
        ok=ok,
        notes=[
            "Measured local Python research implementation only.",
            "Use external baseline drivers for OpenFHE/SEAL/TFHE-rs/Concrete/Lattigo wall-clock comparison.",
        ],
    )


def run_sable_suite(
    preset: str = "fl_demo_clean",
    repetitions: int = 3,
    seed: int = 12345,
    selected_workloads: list[str] | None = None,
) -> BenchmarkSuiteResult:
    """Measure SABLE for selected workloads."""
    if preset not in PRESETS:
        raise ValueError(f"unknown preset: {preset}")
    params = PRESETS[preset]
    selected = selected_workloads or [w.name for w in workloads()]
    results = [run_sable_workload(workload_by_name(name), params, repetitions, seed + 111 * i) for i, name in enumerate(selected)]
    return BenchmarkSuiteResult(
        schema=SCHEMA_SUITE,
        package="sable-he-research",
        version=__version__,
        backend="sable-python-reference",
        preset=preset,
        platform=benchmark_platform(),
        results=results,
        external_baselines=baseline_specs(),
        warning="Measured SABLE results are local Python measurements. External FHE baseline values must be generated independently on the same machine.",
    )


def result_to_plain(obj: Any) -> Any:
    """Recursively convert dataclasses to JSON-friendly structures."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: result_to_plain(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: result_to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [result_to_plain(v) for v in obj]
    return obj


def write_json(path: Path | str, data: Any) -> None:
    """Write JSON with stable formatting."""
    Path(path).write_text(json.dumps(result_to_plain(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_sable_csv(path: Path | str, suite: BenchmarkSuiteResult) -> None:
    """Write a CSV summary of SABLE timing measurements."""
    rows: list[dict[str, Any]] = []
    for result in suite.results:
        for metric, stats in result.timings_ms.items():
            rows.append({
                "backend": result.backend,
                "preset": result.preset,
                "workload": result.workload,
                "family": result.workload_family,
                "metric": metric,
                "count": stats.count,
                "mean_ms": stats.mean_ms,
                "median_ms": stats.median_ms,
                "min_ms": stats.min_ms,
                "max_ms": stats.max_ms,
                "stdev_ms": stats.stdev_ms,
                "ok": result.ok,
            })
    with Path(path).open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["backend"])
        writer.writeheader()
        writer.writerows(rows)


def write_external_result_template(path: Path | str) -> None:
    """Write a JSON template for external FHE library result import."""
    template = {
        "schema": "sable-external-benchmark-results-v1",
        "instructions": "Fill with measured external FHE results from the same machine and workload definitions.",
        "results": [
            {
                "backend": "openfhe",
                "scheme": "BFV",
                "workload": "mul_scalar",
                "metric": "evaluation_time",
                "value": None,
                "unit": "ms",
                "notes": "Replace null with measured wall-clock value.",
            },
            {
                "backend": "tfhe-rs",
                "scheme": "TFHE",
                "workload": "boolean_and",
                "metric": "evaluation_time",
                "value": None,
                "unit": "ms",
                "notes": "Replace null with measured wall-clock value.",
            },
        ],
    }
    write_json(path, template)


def load_external_results(paths: list[str | Path]) -> list[ExternalResult]:
    """Load normalized external benchmark results from JSON/CSV files."""
    results: list[ExternalResult] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            entries = data.get("results", data if isinstance(data, list) else [])
            for item in entries:
                if item.get("value") is None:
                    continue
                results.append(ExternalResult(
                    backend=str(item.get("backend", "unknown")),
                    scheme=str(item.get("scheme", "unknown")),
                    workload=str(item.get("workload", "unknown")),
                    metric=str(item.get("metric", "unknown")),
                    value=float(item.get("value")),
                    unit=str(item.get("unit", "unknown")),
                    source_file=str(path),
                    notes=item.get("notes"),
                ))
        elif path.suffix.lower() == ".csv":
            with path.open("r", encoding="utf-8", newline="") as f:
                for item in csv.DictReader(f):
                    if not item.get("value"):
                        continue
                    results.append(ExternalResult(
                        backend=item.get("backend", "unknown"),
                        scheme=item.get("scheme", "unknown"),
                        workload=item.get("workload", "unknown"),
                        metric=item.get("metric", "unknown"),
                        value=float(item.get("value", "nan")),
                        unit=item.get("unit", "unknown"),
                        source_file=str(path),
                        notes=item.get("notes"),
                    ))
        else:
            raise ValueError(f"unsupported external result file type: {path}")
    return results


def comparison_summary(suite: BenchmarkSuiteResult, external_results: list[ExternalResult]) -> dict[str, Any]:
    """Build a normalized comparison summary without inventing missing baselines."""
    sable_rows = []
    for result in suite.results:
        for metric, stats in result.timings_ms.items():
            sable_rows.append({
                "backend": "sable-python-reference",
                "scheme": "SABLE-HE",
                "workload": result.workload,
                "metric": metric,
                "value": stats.mean_ms,
                "unit": "ms",
                "source": "measured by sable-he benchmark-sable",
            })
    external_rows = [asdict(r) for r in external_results]
    return {
        "schema": "sable-benchmark-comparison-v1",
        "package": "sable-he-research",
        "version": __version__,
        "sable_rows": sable_rows,
        "external_rows": external_rows,
        "missing_external_notice": "External rows are included only if supplied by measured JSON/CSV files.",
    }


def write_benchmark_package(
    output_dir: str | Path,
    preset: str = "fl_demo_clean",
    repetitions: int = 3,
    seed: int = 12345,
    selected_workloads: list[str] | None = None,
) -> dict[str, str]:
    """Write a reproducible benchmark package for reviewers."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    suite = run_sable_suite(preset=preset, repetitions=repetitions, seed=seed, selected_workloads=selected_workloads)
    paths = {
        "suite_json": out / "sable_phase9_sable_benchmark_suite.json",
        "suite_csv": out / "sable_phase9_sable_benchmark_summary.csv",
        "workloads": out / "WORKLOADS.json",
        "baseline_protocol": out / "BASELINE_PROTOCOL.md",
        "external_template": out / "external_baseline_results_template.json",
        "readme": out / "README.md",
    }
    write_json(paths["suite_json"], suite)
    write_sable_csv(paths["suite_csv"], suite)
    write_json(paths["workloads"], {"schema": "sable-benchmark-workloads-v1", "workloads": [asdict(w) for w in workloads()]})
    Path(paths["baseline_protocol"]).write_text(baseline_protocol_markdown(), encoding="utf-8")
    write_external_result_template(paths["external_template"])
    Path(paths["readme"]).write_text(
        "# SABLE-HE Phase 9 benchmark package\n\n"
        "This package contains measured SABLE-HE Python reference timings and templates for measured external FHE baselines.\n\n"
        "Do not treat missing external baseline rows as zero or inferred performance. Run OpenFHE, SEAL, TFHE-rs, Concrete, or Lattigo separately on the same hardware.\n",
        encoding="utf-8",
    )
    return {k: str(v) for k, v in paths.items()}


def run_external_command(command: list[str], timeout: int = 600) -> dict[str, Any]:
    """Run an external benchmark command and capture output.

    This is intentionally generic; it is useful for local benchmark drivers but
    not invoked by default in tests.
    """
    started = time.perf_counter()
    proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    return {
        "command": command,
        "returncode": proc.returncode,
        "elapsed_ms": (time.perf_counter() - started) * 1000.0,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


__all__ = [
    "BenchmarkWorkload", "BaselineSpec", "TimingStats", "SableBenchmarkResult", "BenchmarkSuiteResult", "ExternalResult",
    "benchmark_info", "benchmark_platform", "workloads", "workload_by_name", "baseline_specs", "baseline_protocol_markdown",
    "run_sable_workload", "run_sable_suite", "write_benchmark_package", "write_sable_csv", "write_external_result_template",
    "load_external_results", "comparison_summary", "run_external_command", "result_to_plain", "write_json",
]
