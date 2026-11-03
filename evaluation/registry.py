"""Stage definitions: which tasks each HPC stage runs and how it decides pass/fail.

Stages run in this order: setup -> smoke -> pilot -> crypto, fl -> report.
A task is {"id", "family", "kind", "cfg", "mem_gb", "timeout_s"}.  IDs are
derived from the config, so a rerun of the same commit resumes cleanly.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from itertools import product
from typing import Any, Callable

FL_METHODS_ALL = ["plain", "sable", "lwe", "secagg", "ckks", "bfv", "paillier"]
FL_COST_METHODS = FL_METHODS_ALL + ["sable_ln"]
FL_COST_CLIENTS = [10, 50, 100, 200, 500, 1000]


def _task(family: str, kind: str, cfg: dict[str, Any], mem_gb: float = 2.0, timeout_s: int = 6 * 3600) -> dict[str, Any]:
    key = json.dumps({"kind": kind, "cfg": cfg}, sort_keys=True)
    tid = f"{family}-{hashlib.sha256(key.encode()).hexdigest()[:12]}"
    return {"id": tid, "family": family, "kind": kind, "cfg": cfg, "mem_gb": mem_gb, "timeout_s": timeout_s}


def _fl_cfg(dataset: str, model: str, partition: str, K: int, seed: int, method: str, rounds: int, crypto: str) -> dict[str, Any]:
    cfg: dict[str, Any] = dict(dataset=dataset, model=model, partition=partition, clients=K, seed=seed, method=method,
                               rounds=rounds, local_epochs=1, batch=32, lr=0.05, crypto=crypto, sample_rounds=3)
    if method == "paillier":
        cfg["crypto"] = "sampled"
        cfg["backend_opts"] = {"key_bits": 3072, "coord_limit": 256, "client_limit": 3}
    if method == "sable":  # main row: n=65536, eta=0.003; replicas from the bound (failure <= 1e-12 per coordinate)
        cfg["backend_opts"] = {"n": 65536, "eta": 0.003, "target_failure": 1e-12}
    if method == "sable_ln":  # low-noise row for many clients: n=131072, eta=0.001
        cfg["backend_opts"] = {"n": 131072, "eta": 0.001, "target_failure": 1e-12}
    return cfg


def sable_replicas(method: str, K: int) -> int:
    from sable.fast_regev import choose_replicas

    n, eta = (131072, 0.001) if method == "sable_ln" else (65536, 0.003)
    return choose_replicas(n, 5, 2147483647, eta, K, 1e-12)


def _fl_mem(model: str, K: int, method: str) -> float:
    base = 2.0 + (0.5 if K >= 100 else 0.0) + (0.5 if K >= 200 else 0.0) + (1.0 if K >= 500 else 0.0)
    if method in ("ckks", "bfv", "lwe") and model == "mlp":
        base += 1.5
    if method in ("sable", "sable_ln"):
        d = {"lr": 7850, "mlp": 101770, "cnn": 18378}[model]
        base += 3 * d * sable_replicas(method, K) * 8 / 1e9 + (1.5 if model == "mlp" else 0.5)
    return round(base, 1)


# --------------------------------------------------------------------------- smoke


def smoke_tasks() -> list[dict[str, Any]]:
    ds = os.environ.get("SABLE_SMOKE_DATASET", "mnist")
    t: list[dict[str, Any]] = [
        _task("params", "params_tables", {}),
        _task("corr_agg", "correctness_agg", dict(n=4096, k=5, eta=0.003, R=9, K=10, d=2000, trials=1, seed=0)),
        _task("corr_she", "correctness_she", dict(n=512, k=3, eta=0.002, op="mul", trials=5, seed=0)),
        _task("bench_she", "bench_she", dict(n=1024, k=5, eta=0.0014, reps=1, seed=0, compact_n_c=512, compact_m_c=64)),
        _task("attack2", "attack_two_sparse", dict(n=4096, ratio=10, eta=0.003, seed=0)),
        _task("attack_kp", "attack_known_plaintext", dict(n=256, eta=0.0, seed=0)),
        _task("attack_kp", "attack_known_plaintext", dict(n=256, eta=2**-14, seed=0)),
        _task("ref_presets", "reference_crosscheck", dict(preset="fl_demo_clean", seed=0)),
    ]
    for m in FL_METHODS_ALL:
        opts = {"key_bits": 2048, "coord_limit": 16, "client_limit": 2} if m == "paillier" else {}
        t.append(_task("bench_agg", "bench_agg", dict(method=m, d=2000, K=5, seed=0, rounds=1, backend_opts=opts)))
        cfg = _fl_cfg(ds, "lr", "iid", 5, 0, m, 2, "full")
        if m == "paillier":
            cfg["backend_opts"] = {"key_bits": 2048, "coord_limit": 16, "client_limit": 2}
        t.append(_task("fl", "fl_run", cfg))
    return t


# --------------------------------------------------------------------------- full grids


def crypto_tasks() -> list[dict[str, Any]]:
    from evaluation.crypto.reference import feasible_presets

    t = [_task("params", "params_tables", {})]
    for eta, R, K in product([0.0015, 0.003, 0.006], [5, 9, 15, 25, 51, 101], [10, 50, 100, 250, 500, 1000, 2000]):
        t.append(_task("corr_agg", "correctness_agg", dict(n=65536, k=5, eta=eta, R=R, K=K, d=10000, trials=2, seed=1), mem_gb=3))
    for n, k, eta, op in product([4096, 16384], [3, 4, 5, 6], [0.0007, 0.0014, 0.0028], ["add", "mul", "dot4"]):
        t.append(_task("corr_she", "correctness_she", dict(n=n, k=k, eta=eta, op=op, trials=40, seed=2), mem_gb=3 if n > 4096 else 1.5))
    for n, k in product([4096, 16384, 65536, 131072, 262144], [3, 5, 6]):
        cfg: dict[str, Any] = dict(n=n, k=k, eta=0.0014, reps=3, seed=3)
        if n <= 16384:
            cfg.update(compact_n_c=n, compact_m_c=256)
        mem = 2 + (k + 1) ** 4 * (n + 1) * 40 / 1e9
        t.append(_task("bench_she", "bench_she", cfg, mem_gb=round(mem, 1), timeout_s=12 * 3600))
    for method, d, K in product(["plain", "sable", "sable51", "lwe", "secagg", "ckks", "bfv", "paillier"],
                                [7850, 18378, 101770, 1000000], [10, 100]):
        m = "sable" if method.startswith("sable") else method
        opts: dict[str, Any] = {}
        if method == "sable51":
            opts = {"param_set": "fl_k5_n65536_r51"}
        if m == "paillier":
            opts = {"key_bits": 3072, "coord_limit": 128, "client_limit": 3}
        mem = 2 + (d * 8 * (55 if m == "sable" else 4) / 1e9)
        t.append(_task("bench_agg", "bench_agg", dict(method=m, label=method, d=d, K=K, seed=4, rounds=2, backend_opts=opts),
                       mem_gb=round(mem, 1), timeout_s=12 * 3600))
    for n, ratio, eta, seed in product([4096, 16384, 65536, 131072, 262144], [1, 2, 4, 10, 20], [0.001, 0.003, 0.01, 0.03], [0, 1, 2]):
        t.append(_task("attack2", "attack_two_sparse", dict(n=n, ratio=ratio, eta=eta, seed=seed), mem_gb=1 + n * ratio * 1.2e-6))
    for ratio, eta, seed in product([10, 20], [0.003, 0.01], [0, 1, 2]):
        n = 524288
        t.append(_task("attack2", "attack_two_sparse", dict(n=n, ratio=ratio, eta=eta, seed=seed), mem_gb=1 + n * ratio * 1.2e-6,
                       timeout_s=12 * 3600))
    for n, eta, seed in product([128, 256, 512, 1024, 2048], [0.0, 2**-16, 2**-12, 2**-10, 2**-9, 2**-8, 2**-7], range(10)):
        t.append(_task("attack_kp", "attack_known_plaintext", dict(n=n, eta=eta, seed=seed), mem_gb=1 + (n / 1024) ** 2 * 0.4))
    for eta, seed in product([0.0, 2**-16, 2**-14, 2**-12, 2**-11], range(4)):
        t.append(_task("attack_kp", "attack_known_plaintext", dict(n=4096, eta=eta, seed=seed), mem_gb=4, timeout_s=8 * 3600))
    for preset, seed in product(feasible_presets(), range(3)):
        t.append(_task("ref_presets", "reference_crosscheck", dict(preset=preset, seed=seed)))
    return t


def fl_tasks(rounds: int = 100) -> list[dict[str, Any]]:
    t = []
    # accuracy study: plaintext vs SABLE vs CKKS with real crypto every round
    for ds, model, part, K, seed, m in product(["mnist", "fmnist"], ["lr", "mlp", "cnn"], ["iid", "dir0.5", "dir0.1"],
                                              [10, 50, 100, 200], [0, 1, 2, 3, 4], ["plain", "sable", "ckks"]):
        t.append(_task("fl_acc", "fl_run", _fl_cfg(ds, model, part, K, seed, m, rounds, "full"), mem_gb=_fl_mem(model, K, m), timeout_s=48 * 3600))
    # cost and client-scaling study: every method, K up to 1000, crypto measured on the first 3 rounds
    for model, K, m in product(["lr", "mlp", "cnn"], FL_COST_CLIENTS, FL_COST_METHODS):
        t.append(_task("fl_cost", "fl_run", _fl_cfg("mnist", model, "iid", K, 0, m, rounds, "sampled"), mem_gb=_fl_mem(model, K, m),
                       timeout_s=96 * 3600))
    return t


# --------------------------------------------------------------------------- pilot


PILOT_FAMILIES = ["corr_agg", "corr_she", "bench_she", "bench_agg", "attack2", "attack_kp", "ref_presets", "params", "fl_acc", "fl_cost"]


def pilot_tasks() -> list[dict[str, Any]]:
    """The most expensive member(s) of each family, plus checks for the science."""
    crypto = crypto_tasks()
    fl = fl_tasks(rounds=10)
    pick: list[dict[str, Any]] = []
    def take(pred: Callable[[dict[str, Any]], bool], n: int = 1, pool: list[dict[str, Any]] | None = None) -> None:
        sel = [x for x in (pool or crypto) if pred(x)][:n]
        pick.extend(sel)
    take(lambda x: x["family"] == "params")
    take(lambda x: x["family"] == "corr_agg" and x["cfg"]["K"] == 2000 and x["cfg"]["R"] == 101 and x["cfg"]["eta"] == 0.003)
    take(lambda x: x["family"] == "corr_agg" and x["cfg"]["K"] == 100 and x["cfg"]["R"] == 25 and x["cfg"]["eta"] == 0.003)
    take(lambda x: x["family"] == "corr_she" and x["cfg"]["n"] == 16384 and x["cfg"]["k"] == 6 and x["cfg"]["op"] == "dot4" and x["cfg"]["eta"] == 0.0014)
    take(lambda x: x["family"] == "bench_she" and x["cfg"]["n"] == 65536 and x["cfg"]["k"] == 5)
    take(lambda x: x["family"] == "bench_she" and x["cfg"]["n"] == 16384 and x["cfg"]["k"] == 5)
    take(lambda x: x["family"] == "bench_agg" and x["cfg"]["d"] == 1000000 and x["cfg"]["K"] == 100 and x["cfg"]["label"] in ("sable", "lwe", "ckks", "paillier"), 4)
    take(lambda x: x["family"] == "attack2" and x["cfg"]["n"] == 65536 and x["cfg"]["ratio"] == 20 and x["cfg"]["eta"] == 0.003 and x["cfg"]["seed"] == 0)
    take(lambda x: x["family"] == "attack2" and x["cfg"]["n"] == 262144 and x["cfg"]["ratio"] == 20 and x["cfg"]["eta"] == 0.003 and x["cfg"]["seed"] == 0)
    take(lambda x: x["family"] == "attack_kp" and x["cfg"]["n"] == 2048 and x["cfg"]["eta"] == 2**-12, 2)
    take(lambda x: x["family"] == "attack_kp" and x["cfg"]["n"] == 4096 and x["cfg"]["eta"] == 2**-12)
    take(lambda x: x["family"] == "attack2" and x["cfg"]["n"] == 524288 and x["cfg"]["ratio"] == 20)
    take(lambda x: x["family"] == "ref_presets" and x["cfg"]["seed"] == 0, 20)
    # FL: one run per model size for the three accuracy methods, MNIST, K=100 (the slowest), 10 rounds
    take(lambda x: x["family"] == "fl_acc" and x["cfg"]["dataset"] == "mnist" and x["cfg"]["partition"] == "iid"
         and x["cfg"]["clients"] == 200 and x["cfg"]["seed"] == 0, 9, fl)
    # cost study: every method at the largest K (SABLE main row at K=500; K=1000 needs R=755 and is extrapolated)
    take(lambda x: x["family"] == "fl_cost" and x["cfg"]["model"] == "mlp" and x["cfg"]["clients"] == 1000
         and x["cfg"]["method"] != "sable", 7, fl)
    take(lambda x: x["family"] == "fl_cost" and x["cfg"]["clients"] == 500 and x["cfg"]["method"] == "sable", 3, fl)
    take(lambda x: x["family"] == "fl_cost" and x["cfg"]["clients"] == 1000 and x["cfg"]["method"] == "sable_ln"
         and x["cfg"]["model"] != "mlp", 2, fl)
    return pick


def stage_tasks(stage: str) -> list[dict[str, Any]]:
    return {"smoke": smoke_tasks, "pilot": pilot_tasks, "crypto": crypto_tasks, "fl": fl_tasks}[stage]()


# --------------------------------------------------------------------------- checks


def _ok(results: list[dict[str, Any]], family: str | None = None) -> list[dict[str, Any]]:
    return [r for r in results if r.get("status") == "ok" and (family is None or r["family"] == family)]


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail}


def common_checks(tasks: list[dict[str, Any]], results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    done = {r["id"] for r in results if r.get("status") == "ok"}
    failed = [r["id"] for r in results if r.get("status") != "ok"]
    missing = [t["id"] for t in tasks if t["id"] not in {r["id"] for r in results}]
    return [
        _check("all tasks finished", not missing, f"{len(missing)} tasks never produced a result" if missing else "all tasks have results"),
        _check("no task errors", not failed, f"{len(failed)} failed: {failed[:5]}" if failed else f"{len(done)} tasks ok"),
    ]


def science_checks(stage: str, results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    attack2 = _ok(results, "attack2")
    if attack2:
        strong = [r for r in attack2 if r["cfg"]["ratio"] >= 10 and r["cfg"]["eta"] <= 0.003]
        if strong:
            # a handful of low-degree coordinates can stay wrong after voting; the secret is still broken
            ex = sum(r["result"]["exact"] for r in strong)
            worst = min(r["result"]["fraction_correct"] for r in strong)
            out.append(_check("2-sparse attack recovers >= 99.9% of the secret (ratio>=10, eta<=0.003)", worst >= 0.999,
                              f"{ex}/{len(strong)} exact; worst fraction correct {worst:.6f}"))
    kp = [r for r in _ok(results, "attack_kp") if r["cfg"]["eta"] == 0.0]
    if kp:
        out.append(_check("known-plaintext attack breaks noise-free keys", all(r["result"]["success"] for r in kp), f"{len(kp)} runs"))
    ref = [r for r in _ok(results, "ref_presets") if r["result"]["eta"] == 0.0]
    if ref:
        out.append(_check("noise-free reference presets broken", all(r["result"]["success"] for r in ref), f"{len(ref)} runs"))
    agg = _ok(results, "corr_agg")
    if agg:
        # empirical failure rate must not exceed the analytic bound by a margin (bound is an upper bound)
        bad = [r for r in agg if r["result"]["coord_failure_rate"] > max(1.5 * r["result"]["failure_bound"], 5.0 / r["result"]["coords"])]
        out.append(_check("aggregation failures within analytic bound", not bad, f"{len(bad)} configs exceed bound"))
    she = [r for r in _ok(results, "corr_she") if r["cfg"]["eta"] <= 0.002 and r["cfg"]["op"] == "mul" and r["cfg"]["k"] <= 5]
    if she:
        low = [r["cfg"] for r in she if r["result"]["p_replica_correct"] < 0.3]
        out.append(_check("SHE multiply per-replica correctness >= 0.3 (k<=5, eta<=0.002)", not low,
                          f"{len(low)} of {len(she)} configs below 0.2" if low else f"{len(she)} configs ok"))
    bagg = _ok(results, "bench_agg")
    if bagg:
        exact = [r for r in bagg if r["result"]["backend"]["exact"] and r["cfg"]["method"] not in ("paillier",)]
        bad = [r["cfg"]["method"] for r in exact if r["result"].get("coord_failures", 0) > 0 and r["cfg"]["method"] != "sable"]
        out.append(_check("exact baselines aggregate without error", not bad, f"failing: {sorted(set(bad))}" if bad else "ok"))
    fl = [r for r in results if r["family"] in ("fl", "fl_acc", "fl_cost") and r.get("status") == "ok"]
    if fl:
        real = [r for r in fl if r["cfg"]["dataset"] in ("mnist", "fmnist")]
        plain = [r for r in real if r["cfg"]["method"] == "plain"]
        if plain:
            thr = 0.5 if stage == "smoke" else 0.8
            lr_mnist = [r for r in plain if r["cfg"]["dataset"] == "mnist"]
            if lr_mnist:
                acc = min(r["result"]["final_test_acc"] for r in lr_mnist)
                out.append(_check(f"plain FedAvg on MNIST reaches >= {thr}", acc >= thr, f"min final acc {acc:.3f}"))
        by_key: dict[tuple, dict[str, float]] = {}
        for r in fl:
            c = r["cfg"]
            key = (c["dataset"], c["model"], c["partition"], c["clients"], c["seed"], c["rounds"])
            by_key.setdefault(key, {})[c["method"]] = r["result"]["final_test_acc"]
        gaps = [abs(v[m] - v["plain"]) for v in by_key.values() for m in ("sable", "sable_ln") if m in v and "plain" in v]
        if gaps:
            out.append(_check("SABLE FedAvg matches plaintext accuracy (|gap| <= 0.01)", max(gaps) <= 0.01, f"max gap {max(gaps):.4f} over {len(gaps)} pairs"))
        sable_fail = sum(r["result"]["total_coord_failures"] for r in fl if r["cfg"]["method"] in ("sable", "sable_ln"))
        out.append(_check("SABLE decoding failures in FL runs", sable_fail == 0 or stage in ("crypto", "fl"), f"{sable_fail} coordinate failures"))
    return out


FL_FAMILIES = ("fl", "fl_acc", "fl_cost")
TASK_OVERHEAD_S = 10.0  # process spawn and imports


def _cost_units(t: dict[str, Any]) -> float:
    """Relative cost of a task inside its family (calibrated by the pilot)."""
    f, c = t["family"], t["cfg"]
    if f == "bench_she":
        return (c["n"] + 1) * (c["k"] + 1) ** 4 * c.get("reps", 3)
    if f == "corr_she":
        return (c["n"] + 1) * (c["k"] + 1) ** 4 * c["trials"] * {"add": 0.1, "mul": 1.0, "dot4": 4.0}[c["op"]]
    if f == "corr_agg":
        return float(c["K"] * c["R"] * c["d"] * c["trials"])
    if f == "attack2":
        return float(c["n"] * c["ratio"])
    if f == "attack_kp":
        return float((c["n"] + 1) ** 3)
    if f == "bench_agg":
        return float(c["d"] * c["K"] * c.get("rounds", 2))
    if f in FL_FAMILIES:
        units = float(c["rounds"] * c["clients"])
        if c["method"] in ("sable", "sable_ln"):  # SABLE cost per client grows with the replica count
            units *= sable_replicas(c["method"], c["clients"])
        return units
    return 1.0


def _cost_group(t: dict[str, Any]) -> tuple:
    f, c = t["family"], t["cfg"]
    if f in FL_FAMILIES:
        return (f, c["model"], c["method"])
    if f == "bench_agg":
        return (f, c.get("label", c["method"]))
    return (f,)


def _replica_factor(cfg: dict[str, Any]) -> float:
    return float(sable_replicas(cfg["method"], cfg["clients"])) if cfg["method"] in ("sable", "sable_ln") else 1.0


def _fl_round_rates(r: dict[str, Any]) -> tuple[float, float] | None:
    """(seconds per encrypted round per client per replica, seconds per plain round per client) from a pilot run."""
    hist = r.get("result", {}).get("history", [])
    if not hist or "round_wall_s" not in hist[0]:
        return None
    K = r["cfg"]["clients"]
    enc = [h["round_wall_s"] for h in hist if h.get("measured")]
    pln = [h["round_wall_s"] for h in hist if not h.get("measured")]
    c = (max(enc) / (K * _replica_factor(r["cfg"]))) if enc else 0.0
    p = (max(pln) / K) if pln else 0.0
    return c, p


def pilot_projection(results: list[dict[str, Any]], workers: int, mem_gb: float) -> dict[str, Any]:
    """Project full-stage wall time from pilot timings.

    Crypto families use a cost model (_cost_units) whose rate comes from the
    pilot.  FL runs use per-round wall times recorded by the pilot runs:
    encrypted rounds scale with clients x replicas, plain rounds with clients.
    A group the pilot did not run uses the slowest rate of the same method
    (FL) or family (crypto), so the estimate errs on the long side.  Wall time
    is the larger of the total work spread over the workers and the single
    longest task.
    """
    group_rate: dict[tuple, float] = {}
    fam_rate: dict[str, float] = {}
    fl_group: dict[tuple, list[float]] = {}
    fl_method: dict[tuple, list[float]] = {}
    for r in results:
        if r.get("status") != "ok":
            continue
        f = r["family"]
        if f in FL_FAMILIES:
            rates = _fl_round_rates(r)
            if rates is None:
                continue
            for key, store in (((f, r["cfg"]["model"], r["cfg"]["method"]), fl_group), ((f, r["cfg"]["method"]), fl_method)):
                cur = store.setdefault(key, [0.0, 0.0])
                cur[0], cur[1] = max(cur[0], rates[0]), max(cur[1], rates[1])
            continue
        rate = max(0.0, r["seconds"] - TASK_OVERHEAD_S) / max(_cost_units(r), 1e-12)
        g = _cost_group(r)
        group_rate[g] = max(group_rate.get(g, 0.0), rate)
        fam_rate[f] = max(fam_rate.get(f, 0.0), rate)
    # a plain-round rate missing for a group (fully encrypted runs) falls back to the method's
    plain_by_model: dict[tuple, float] = {}
    for (f, model, method), (c, p) in fl_group.items():
        plain_by_model[(f, model)] = max(plain_by_model.get((f, model), 0.0), p)
    par = max(1, min(workers, int(mem_gb // 3) or 1))
    proj: dict[str, Any] = {}
    for stage, tasks in (("crypto", crypto_tasks()), ("fl", fl_tasks())):
        total, longest, uncalibrated = 0.0, 0.0, 0
        for t in tasks:
            f, c = t["family"], t["cfg"]
            if f in FL_FAMILIES:
                rates = fl_group.get((f, c["model"], c["method"])) or fl_method.get((f, c["method"]))
                if rates is None:
                    uncalibrated += 1
                    continue
                enc_rounds = c["rounds"] if c.get("crypto", "full") == "full" else min(c["rounds"], c.get("sample_rounds", 2))
                plain_rate = rates[1] or plain_by_model.get(("fl_cost", c["model"]), 0.0) or plain_by_model.get(("fl_acc", c["model"]), 0.0)
                est = TASK_OVERHEAD_S + enc_rounds * rates[0] * c["clients"] * _replica_factor(c) \
                    + (c["rounds"] - enc_rounds) * plain_rate * c["clients"]
            else:
                rate = group_rate.get(_cost_group(t), fam_rate.get(f))
                if rate is None:
                    uncalibrated += 1
                    continue
                est = TASK_OVERHEAD_S + rate * _cost_units(t)
            total += est
            longest = max(longest, est)
        wall = max(total / par * 1.25, longest * 1.1)
        proj[stage] = {"tasks": len(tasks), "uncalibrated_tasks": uncalibrated, "cpu_hours": total / 3600,
                       "longest_task_hours": longest / 3600, "parallel_workers": par, "projected_wall_hours": wall / 3600}
    return proj


def stage_checks(stage: str, tasks: list[dict[str, Any]], results: list[dict[str, Any]],
                 projection: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    checks = common_checks(tasks, results) + science_checks(stage, results)
    if stage == "pilot" and projection:
        for s in ("crypto", "fl"):
            h = projection[s]["projected_wall_hours"]
            unc = projection[s]["uncalibrated_tasks"]
            checks.append(_check(f"projected {s} stage fits in 9 days", h < 9 * 24 and unc == 0,
                                 f"{h:.1f} h projected (longest task {projection[s]['longest_task_hours']:.1f} h, "
                                 f"{unc} tasks without a pilot timing)"))
    return checks
