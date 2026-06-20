"""Command-line interface for the SABLE-HE research package."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any

from . import operations as ops
from . import fl
from . import fl
from .baselines import default_workloads, flatten_for_csv, model_comparison
from .c7_relation_screen import estimate_c7_relations, format_c7_report
from .estimator import estimate, format_estimate
from .fl import EncryptedFLAggregator, PlainFLAggregator, fl_capabilities
from .params import PRESETS
from .sable import compact_c7, decrypt_c7, encrypt, expand, keygen_c7
from .version import __release_name__, __version__


def _json_default(obj: Any) -> Any:
    try:
        return asdict(obj)
    except TypeError:
        return str(obj)


def _encrypt_expand(kp: Any, value: int, seed: int) -> Any:
    return expand(kp, encrypt(kp, value, seed=seed))


def _expected(operation: str, x: int, y: int, q: int, scalar: int = 3, exponent: int = 3) -> int:
    x %= q
    y %= q
    formulas = {
        "add": x + y,
        "sub": x - y,
        "neg": -x,
        "scalar3": scalar * x,
        "mul": x * y,
        "square": x * x,
        "pow3": pow(x, exponent, q),
        "not": 1 - x,
        "and": x * y,
        "or": x + y - x * y,
        "xor": x + y - 2 * x * y,
        "nand": 1 - x * y,
        "nor": 1 - (x + y - x * y),
        "xnor": 1 - (x + y - 2 * x * y),
        "implies": 1 - x + x * y,
    }
    if operation not in formulas:
        raise ValueError(f"unknown operation: {operation}")
    return formulas[operation] % q


def _apply_operation(operation: str, x_ct: Any, y_ct: Any) -> Any:
    if operation == "add":
        return ops.add(x_ct, y_ct)
    if operation == "sub":
        return ops.sub(x_ct, y_ct)
    if operation == "neg":
        return ops.neg(x_ct)
    if operation == "scalar3":
        return ops.scalar_mul(x_ct, 3)
    if operation == "mul":
        return ops.mul(x_ct, y_ct)
    if operation == "square":
        return ops.square(x_ct)
    if operation == "pow3":
        return ops.pow_plain(x_ct, 3)
    if operation == "not":
        return ops.gate_not(x_ct)
    if operation == "and":
        return ops.gate_and(x_ct, y_ct)
    if operation == "or":
        return ops.gate_or(x_ct, y_ct)
    if operation == "xor":
        return ops.gate_xor(x_ct, y_ct)
    if operation == "nand":
        return ops.gate_nand(x_ct, y_ct)
    if operation == "nor":
        return ops.gate_nor(x_ct, y_ct)
    if operation == "xnor":
        return ops.gate_xnor(x_ct, y_ct)
    if operation == "implies":
        return ops.gate_implies(x_ct, y_ct)
    raise ValueError(f"unknown operation: {operation}")


def cmd_version(args: argparse.Namespace) -> int:
    del args
    print(f"sable-he-research {__version__} ({__release_name__})")
    print("Status: research and validation release; no certified parameter set.")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    del args
    print(f"SABLE-HE research package {__version__} ({__release_name__})")
    print("Status: research and validation release; no certified parameter set.")
    print("Available presets:")
    for name in sorted(PRESETS):
        p = PRESETS[name]
        marker = " [default]" if name == "c7_standard_toy_clean" else ""
        print(f"  - {name}: q={p.q}, n={p.n}, k={p.k}, replicas={p.replicas}{marker}")
    return 0


def cmd_presets(args: argparse.Namespace) -> int:
    rows = []
    for name in sorted(PRESETS):
        p = PRESETS[name]
        row = asdict(p)
        rows.append(row)
    if args.json:
        print(json.dumps(rows, indent=2, default=_json_default))
    else:
        for row in rows:
            print(
                f"{row['name']:<28} q={row['q']:<7} n={row['n']:<5} k={row['k']:<2} "
                f"eta={row['eta']:<10g} n_c={row['n_c']:<5} m_c={row['m_c']:<5} R={row['replicas']}"
            )
    return 0


def cmd_estimate(args: argparse.Namespace) -> int:
    result = estimate(PRESETS[args.preset], depth=args.depth, additions=args.additions, target_bits=args.target_bits)
    if args.json:
        print(json.dumps(result, indent=2, default=_json_default))
    else:
        print(format_estimate(result))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    params = PRESETS[args.preset]
    kp = keygen_c7(params, seed=args.seed, mode="coordinate")
    x = args.x % params.q
    y = args.y % params.q
    x_ct = _encrypt_expand(kp, x, args.seed + 101)
    y_ct = _encrypt_expand(kp, y, args.seed + 202)
    result_ct = _apply_operation(args.operation, x_ct, y_ct)
    observed = decrypt_c7(kp, compact_c7(kp, result_ct))
    expected = _expected(args.operation, x, y, params.q)
    payload = {
        "package": "sable-he-research",
        "version": __version__,
        "status": "validation demo; no certified parameter set",
        "preset": args.preset,
        "q": params.q,
        "operation": args.operation,
        "x": x,
        "y": y,
        "expected": expected,
        "observed": observed,
        "ok": observed == expected,
    }
    if args.json:
        print(json.dumps(payload, indent=2, default=_json_default))
    else:
        print(f"SABLE-HE {__version__} demo ({__release_name__})")
        print(f"preset={args.preset} q={params.q} operation={args.operation}")
        print(f"expected={expected} observed={observed} passes={observed == expected}")
        print("status: validation demo; not a certified cryptographic parameter set")
    return 0 if observed == expected else 2


def cmd_quickstart(args: argparse.Namespace) -> int:
    args.operation = "mul"
    return cmd_run(args)


def cmd_compare(args: argparse.Namespace) -> int:
    rows = [model_comparison(PRESETS[args.preset], workload) for workload in default_workloads()]
    if args.json:
        print(json.dumps(rows, indent=2, default=_json_default))
    else:
        for row in rows:
            flat = flatten_for_csv(row)
            print(
                f"{flat['params']} {flat['workload']}: depth={flat['depth']} "
                f"mul={flat['multiplications']} add={flat['additions']} "
                f"SABLE-mul-proxy={flat['sable_multiplication_cost_proxy']} "
                f"TFHE-gate-proxy={flat['boolean_gate_proxy']} "
                f"failure-bound={flat['sable_final_failure_bound']:.3g}"
            )
        print("Proxy model only; use external OpenFHE/SEAL/TFHE-rs benchmarks for wall-clock comparisons.")
    return 0


def cmd_self_test(args: argparse.Namespace) -> int:
    failures: list[str] = []
    for i, operation in enumerate(["add", "sub", "mul", "square", "scalar3", "and", "or", "xor", "not".replace("not", "implies")]):
        ns = argparse.Namespace(
            preset=args.preset,
            operation=operation,
            x=1 if operation in {"and", "or", "xor", "implies"} else 3,
            y=0 if operation in {"and", "or", "xor", "implies"} else 5,
            seed=args.seed + 17 * i,
            json=True,
        )
        rc = cmd_run(ns)
        if rc != 0:
            failures.append(operation)
    if failures:
        print("Self-test failed: " + ", ".join(failures))
        return 1
    print(f"Self-test passed for preset {args.preset}")
    print("status: validation demo; no certified parameter set")
    return 0


def cmd_readiness(args: argparse.Namespace) -> int:
    gates = [
        ("GREEN", "research_artifact", "construction, paper, prototype, tests, and limitation trail are present"),
        ("GREEN", "internal_validation", "toy correctness, arithmetic tests, estimators, and relation screens are automated"),
        ("GREEN", "audit_package", "suitable for independent cryptanalysis with limitations disclosed"),
        ("RED", "production_cryptography", "requires independent cryptanalysis, hardened implementation, side-channel review, audit, and stable parameters"),
        ("RED", "certified_secure_parameters", "requires externally reviewed parameter security and attack-cost estimates"),
        ("AMBER", "standardization_ready", "draft materials exist, but parameters and external cryptanalysis are not frozen"),
    ]
    payload = {
        "project": "SABLE-HE Research Package",
        "version": __version__,
        "gates": [{"status": s.lower(), "gate": g, "meaning": m} for s, g, m in gates],
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for status, gate, meaning in gates:
            print(f"{status:5s}  {gate}: {meaning}")
    return 0





def cmd_fl_capabilities(args: argparse.Namespace) -> int:
    rows = [cap.__dict__ for cap in fl_capabilities()]
    if args.json:
        print(json.dumps(rows, indent=2, default=_json_default))
    else:
        print("method                 encrypted-native   plaintext/tensor   notes")
        print("-" * 78)
        for cap in fl_capabilities():
            enc = "yes" if cap.encrypted_native else "no"
            plain = "yes" if cap.plaintext_tensor else "no"
            print(f"{cap.method:<22} {enc:<18} {plain:<16} {cap.notes}")
    return 0


def cmd_fl_demo(args: argparse.Namespace) -> int:
    params = PRESETS[args.preset]
    aggregator = EncryptedFLAggregator.from_params(params, key_seed=args.seed, scale=args.scale, seed=args.seed + 10000)
    client_models = [
        [0.12, -0.34, 1.20],
        [0.10, -0.30, 1.25],
        [0.20, -0.40, 1.10],
    ]
    sample_counts = [80, 20, 100]
    encrypted = [aggregator.encrypt_model(model, seed=args.seed + 1000 * i) for i, model in enumerate(client_models)]
    encrypted_avg = aggregator.fedavg(encrypted, sample_counts)
    observed = aggregator.decrypt_model(encrypted_avg)
    plain = PlainFLAggregator().fedavg(client_models, sample_counts)
    payload = {
        "package": "sable-he-research",
        "version": __version__,
        "preset": args.preset,
        "q": params.q,
        "scale": args.scale,
        "method": "fedavg",
        "sample_counts": sample_counts,
        "encrypted_result": observed,
        "plaintext_reference": plain,
    }
    if args.json:
        print(json.dumps(payload, indent=2, default=_json_default))
    else:
        print(f"SABLE-HE FL demo {__version__} ({__release_name__})")
        print(f"preset={args.preset} q={params.q} scale={args.scale}")
        print(f"sample_counts={sample_counts}")
        print(f"encrypted FedAvg result={observed}")
        print(f"plaintext reference   ={plain}")
    return 0


def cmd_screen_c7(args: argparse.Namespace) -> int:
    report = estimate_c7_relations(
        PRESETS[args.preset],
        block_size=args.block_size,
        mode=args.mode,
        basis_size=args.basis_size,
        max_terms_per_block=args.max_terms_per_block,
        relation_screen_weight=args.relation_screen_weight,
        target_bits=args.target_bits,
        seed=args.seed,
    )
    if args.json:
        print(json.dumps(report.to_jsonable(), indent=2, default=_json_default))
    else:
        print(format_c7_report(report))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sable-he",
        description="SABLE-HE research prototype command-line tools",
    )
    parser.add_argument("--version", action="version", version=f"sable-he-research {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("version", help="print package version and status")
    p.set_defaults(func=cmd_version)

    p = sub.add_parser("info", help="show package status and parameter presets")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("presets", help="list bundled validation/research parameter presets")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_presets)

    p = sub.add_parser("estimate", help="run the built-in correctness/size/security screen")
    p.add_argument("--preset", default="c7_standard_toy_clean", choices=sorted(PRESETS))
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--additions", type=int, default=1)
    p.add_argument("--target-bits", type=int, default=128)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_estimate)

    operations = ["add", "sub", "neg", "scalar3", "mul", "square", "pow3", "not", "and", "or", "xor", "nand", "nor", "xnor", "implies"]
    p = sub.add_parser("run", help="evaluate one encrypted arithmetic or Boolean operation")
    p.add_argument("operation", choices=operations)
    p.add_argument("--preset", default="c7_standard_toy_clean", choices=sorted(PRESETS))
    p.add_argument("--x", type=int, default=1)
    p.add_argument("--y", type=int, default=0)
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--key-seed", type=int, default=None, help="alias for --seed")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=lambda a: (setattr(a, "seed", a.key_seed) if a.key_seed is not None else None) or cmd_run(a))

    p = sub.add_parser("demo", help="alias-style demo command with --operation")
    p.add_argument("--operation", default="mul", choices=operations)
    p.add_argument("--preset", default="c7_standard_toy_clean", choices=sorted(PRESETS))
    p.add_argument("--x", type=int, default=3)
    p.add_argument("--y", type=int, default=5)
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("quickstart", help="run a deterministic encrypted multiplication demo")
    p.add_argument("--preset", default="c7_standard_toy_clean", choices=sorted(PRESETS))
    p.add_argument("--x", type=int, default=3)
    p.add_argument("--y", type=int, default=5)
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_quickstart)

    p = sub.add_parser("compare", help="proxy comparisons to TFHE/FHEW, BFV/BGV, and CKKS families")
    p.add_argument("--preset", default="c7_standard_toy_clean", choices=sorted(PRESETS))
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("baselines", help="alias for compare")
    p.add_argument("--preset", default="c7_standard_toy_clean", choices=sorted(PRESETS))
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser("self-test", help="run a quick end-to-end operation check")
    p.add_argument("--preset", default="c7_standard_toy_clean", choices=sorted(PRESETS))
    p.add_argument("--seed", type=int, default=2026)
    p.set_defaults(func=cmd_self_test)

    p = sub.add_parser("screen-c7", help="run the C7 relation-surface screen")
    p.add_argument("--preset", default="c7_standard_toy_noisy", choices=sorted(PRESETS))
    p.add_argument("--block-size", type=int, default=None)
    p.add_argument("--mode", default="standard", choices=["standard", "coordinate", "screened-random"])
    p.add_argument("--basis-size", type=int, default=None)
    p.add_argument("--max-terms-per-block", type=int, default=None)
    p.add_argument("--relation-screen-weight", type=int, default=3)
    p.add_argument("--target-bits", type=float, default=128.0)
    p.add_argument("--seed", type=int, default=777)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_screen_c7)


    p = sub.add_parser("fl-capabilities", help="show FL aggregation support matrix")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_fl_capabilities)

    p = sub.add_parser("fl-methods", help="alias for fl-capabilities")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_fl_capabilities)

    p = sub.add_parser("fl-demo", help="run encrypted FedAvg on small model-weight arrays")
    p.add_argument("--preset", default="fl_demo_clean", choices=sorted(PRESETS))
    p.add_argument("--scale", type=int, default=1000)
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_fl_demo)

    p = sub.add_parser("readiness", help="print readiness gates and limitations")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_readiness)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except BrokenPipeError:
        return 1
    except Exception as exc:  # pragma: no cover
        print(f"sable-he: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
